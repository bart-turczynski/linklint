/**
 * Live TLS certificate evidence enricher (LINK-lmvldqop, M7b).
 *
 * Wraps the M7a observational TLS capability as a core {@link Enricher}. For an
 * HTTPS input it inspects the original hostname's certificate through the safe
 * pinned transport and emits a source-attributed `tls.certificate` evidence
 * artifact: the normalized leaf (subject, issuer, SANs, certificate-policy OIDs and
 * DV/OV/EV posture, validity window, self-issued state) together with the three
 * independent validation axes (chain trust, hostname match, validity) and any
 * structured defects.
 *
 * This slice is evidence-only. Certificate state is neutral on its own — DV alone
 * is not risk — so NO scored finding is projected. A TLS connection/validation
 * problem is an explicit `skipped`/`failure` outcome, never a safety claim: a
 * prohibited destination or cancellation is `skipped`; a handshake or
 * certificate-analysis failure is `failure`. Non-HTTPS or hostless input is
 * `skipped` without any connection attempt.
 */

import {
  ENRICHMENT_SCHEMA_VERSION,
  type Enricher,
  type EnrichmentCause,
  type EnrichmentEvidence,
  type EnrichmentOutcome,
  type EnrichmentProvenance,
  type EnrichmentReport,
  type EnrichmentSubject,
  type InspectResult,
} from "linklint";

import { freshnessFor } from "../sources/index.js";
import type {
  NormalizedTlsObservation,
  SafeTlsInspector,
  TlsObservationCauseCode,
} from "../transport/index.js";
import {
  TLS_CERTIFICATE_EVIDENCE_TYPE,
  TLS_SOURCE_DESCRIPTOR,
  TLS_SOURCE_ID,
  TLS_SOURCE_VERSION,
} from "./tls-descriptor.js";

export interface TlsCertificateEnricherOptions {
  /** The M7a observational TLS inspector (deterministic fixture in tests). */
  readonly inspector: SafeTlsInspector;
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
}

/**
 * Build the live TLS certificate enricher. It inspects the HTTPS origin's
 * certificate and emits `tls.certificate` evidence; it never scores a finding.
 */
export function createTlsCertificateEnricher(options: TlsCertificateEnricherOptions): Enricher {
  const now = options.now ?? (() => new Date());

  return {
    id: TLS_SOURCE_ID,
    layer: "reputation",
    async enrich(result: InspectResult): Promise<EnrichmentReport> {
      const observedAt = now();
      const host = result.parsed?.effectiveHost ?? null;
      const scheme = result.parsed?.scheme ?? null;

      if (scheme !== "https" || host === null || host === "") {
        return report(
          skippedOutcome({ kind: "url", value: result.input }, observedAt, {
            code: "tls-not-https-endpoint",
            message: "input is not an absolute HTTPS URL with a host",
            retryable: false,
          }),
        );
      }

      const subject: EnrichmentSubject = { kind: "host", value: host };
      const url = inspectionUrl(host, result.parsed?.port ?? null);
      const outcome = await options.inspector.inspect({ url });

      switch (outcome.status) {
        case "observed":
          return report(observedOutcome(subject, observedAt, outcome.observation));
        case "blocked":
        case "incomplete": {
          const disposition = dispositionFor(outcome.cause.code);
          return report(
            degradedOutcome(disposition.status, subject, observedAt, {
              code: `tls-${outcome.cause.code}`,
              message: `TLS inspection did not complete: ${outcome.cause.code}`,
              retryable: disposition.retryable,
              ...(outcome.cause.details ? { details: outcome.cause.details } : {}),
            }),
          );
        }
      }
    },
  };
}

function observedOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  observation: NormalizedTlsObservation,
): EnrichmentOutcome {
  const observedIso = observedAt.toISOString();
  const freshness = freshnessFor(TLS_SOURCE_DESCRIPTOR.freshness, observedAt, null);
  const { leaf, validation } = observation;

  const evidence: EnrichmentEvidence = {
    type: TLS_CERTIFICATE_EVIDENCE_TYPE,
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      serverName: observation.serverName,
      protocolVersion: observation.protocolVersion,
      chainDepth: observation.chainDepth,
      subject: leaf.subject,
      issuer: leaf.issuer,
      serialNumber: leaf.serialNumber,
      subjectAltNames: [...leaf.subjectAltNames],
      policyOids: [...leaf.policyOids],
      assuranceLevel: leaf.assuranceLevel,
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
      selfIssued: leaf.selfIssued,
      chainTrusted: validation.chainTrusted,
      hostnameMatch: validation.hostnameMatch,
      withinValidity: validation.withinValidity,
      defects: [...validation.defects],
    },
  };

  // Evidence-only: certificate state is neutral, so no finding is ever projected.
  return {
    sourceId: TLS_SOURCE_ID,
    layer: "reputation",
    status: "success",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    evidence: [evidence],
    findings: [],
  };
}

interface Disposition {
  readonly status: "skipped" | "failure";
  readonly retryable: boolean;
}

/**
 * Map a transport observation cause to an enrichment disposition. A refused
 * destination or cancellation/timeout is a `skipped` non-result; a network,
 * handshake, or certificate-analysis problem is a `failure`. `blocked` (a
 * prohibited pinned address) is transport-policy refusal, so it skips.
 */
function dispositionFor(code: TlsObservationCauseCode): Disposition {
  switch (code) {
    case "prohibited-address":
    case "invalid-url":
    case "unsupported-scheme":
    case "url-credentials":
      return { status: "skipped", retryable: false };
    case "caller-aborted":
    case "timeout":
      return { status: "skipped", retryable: true };
    case "certificate-malformed":
    case "certificate-too-large":
    case "chain-too-deep":
      return { status: "failure", retryable: false };
    default:
      // dns-*, connect-*, connection-address-mismatch, tls-handshake
      return { status: "failure", retryable: true };
  }
}

function skippedOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return degradedOutcome("skipped", subject, observedAt, cause);
}

function degradedOutcome(
  status: "skipped" | "failure",
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return {
    sourceId: TLS_SOURCE_ID,
    layer: "reputation",
    status,
    subject,
    observedAt: observedAt.toISOString(),
    provenance: provenance(),
    freshness: { status: "unknown", expiresAt: null },
    evidence: [],
    findings: [],
    cause: {
      code: cause.code,
      message: cause.message,
      retryable: cause.retryable,
      ...(cause.details ? { details: cause.details } : {}),
    },
  };
}

/** Build the HTTPS origin URL to inspect, bracketing IPv6 literals. */
function inspectionUrl(host: string, port: number | null): string {
  const authority = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const portPart = port !== null && port !== 443 ? `:${port}` : "";
  return `https://${authority}${portPart}/`;
}

function provenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: { name: TLS_SOURCE_ID, version: TLS_SOURCE_VERSION },
    data: { name: "tls.inspected-origin" },
  };
}

function report(outcome: EnrichmentOutcome): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes: [outcome] };
}
