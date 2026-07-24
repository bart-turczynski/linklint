/**
 * DNS state evidence enricher (LINK-diataibn, M9a1).
 *
 * Wraps the injected {@link DnsResolverPort} as a core {@link Enricher}. For a
 * host-bearing input it queries A and AAAA on the effective host and NS and MX on
 * the registrable domain (the zone apex where delegation and mail live), then
 * normalizes the four answers into one `dns.records` evidence artifact: the
 * per-type answer state, addresses, nameservers, mail exchanges, the derived mail
 * semantic (explicit / null / implicit-A / none), and record TTLs. It also emits a
 * second `dns.dnssec` artifact carrying the zone's DNSSEC validation state
 * (secure / insecure / bogus / indeterminate) and whether the resolver validates.
 *
 * This slice is evidence-only. DNS state is neutral on its own — an NXDOMAIN
 * answer, a null MX, an unsigned (`insecure`) or even validation-failed (`bogus`)
 * zone is neither safe nor malicious — so NO finding is ever projected. Evidence is emitted whenever at least one query returned an
 * authoritative answer (including authoritative negatives). When NO query could
 * be answered (all SERVFAIL / REFUSED / timeout / abort / error), the outcome is
 * an explicit `skipped`/`failure` with a structured cause and empty evidence,
 * never a fabricated result. Hostless or IP-literal input is `skipped` without a
 * lookup.
 */

import {
  ENRICHMENT_SCHEMA_VERSION,
  type Enricher,
  type EnrichmentCause,
  type EnrichmentContext,
  type EnrichmentEvidence,
  type EnrichmentOutcome,
  type EnrichmentProvenance,
  type EnrichmentReport,
  type EnrichmentSubject,
  type InspectResult,
} from "linklint";

import { freshnessFor } from "../sources/index.js";
import {
  DNS_DNSSEC_EVIDENCE_TYPE,
  DNS_RECORDS_EVIDENCE_TYPE,
  DNS_SOURCE_DESCRIPTOR,
  DNS_SOURCE_ID,
  DNS_SOURCE_VERSION,
} from "./dns-descriptor.js";
import type {
  DnsAnswer,
  DnsResolverPort,
  DnsUnresolvedState,
  DnssecAnswer,
} from "./dns-types.js";
import { normalizeDnsState, type NormalizedDnsState } from "./dns-normalize.js";

export interface DnsStateEnricherOptions {
  /** Provider-scoped DNS resolver port (deterministic fixture in tests). */
  readonly resolver: DnsResolverPort;
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
}

/**
 * Build the DNS state enricher. It observes A/AAAA/NS/MX for the inspected host
 * and emits `dns.records` evidence; it never scores a finding.
 */
export function createDnsStateEnricher(options: DnsStateEnricherOptions): Enricher {
  const now = options.now ?? (() => new Date());

  return {
    id: DNS_SOURCE_ID,
    layer: "reputation",
    async enrich(result: InspectResult, ctx: EnrichmentContext): Promise<EnrichmentReport> {
      const observedAt = now();
      const host = result.parsed?.effectiveHost ?? null;
      const isIp = result.parsed?.isIp === true;

      if (host === null || host === "") {
        return report(
          degradedOutcome("skipped", { kind: "url", value: result.input }, observedAt, {
            code: "dns-no-host",
            message: "input has no host to resolve",
            retryable: false,
          }),
        );
      }

      const subject: EnrichmentSubject = { kind: "host", value: host };

      if (isIp) {
        return report(
          degradedOutcome("skipped", subject, observedAt, {
            code: "dns-not-a-hostname",
            message: "input host is an IP literal; nothing to resolve",
            retryable: false,
          }),
        );
      }

      const zone = result.parsed?.registrableDomain ?? host;
      const signal = ctx.signal;

      // DNSSEC validation is evaluated on the zone (the apex where signing lives)
      // in the same parallel batch. Its port resolves for every outcome — an
      // unknown state collapses to `indeterminate`, never a rejection — so it can
      // never fail the whole enrichment; the record queries alone govern the
      // skipped/failure disposition below.
      const [a, aaaa, ns, mx, dnssec] = await Promise.all([
        options.resolver.query({ name: host, type: "A", ...signalOpt(signal) }),
        options.resolver.query({ name: host, type: "AAAA", ...signalOpt(signal) }),
        options.resolver.query({ name: zone, type: "NS", ...signalOpt(signal) }),
        options.resolver.query({ name: zone, type: "MX", ...signalOpt(signal) }),
        options.resolver.validateDnssec({ name: zone, ...signalOpt(signal) }),
      ]);

      const state = normalizeDnsState({ host, zone, a, aaaa, ns, mx });

      if (!state.authoritative) {
        const disposition = dominantFailure([a, aaaa, ns, mx]);
        return report(
          degradedOutcome(disposition.status, subject, observedAt, {
            code: disposition.code,
            message: `no DNS query could be answered (${disposition.reason})`,
            retryable: disposition.retryable,
          }),
        );
      }

      return report(observedOutcome(subject, observedAt, state, dnssec));
    },
  };
}

function observedOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  state: NormalizedDnsState,
  dnssec: DnssecAnswer,
): EnrichmentOutcome {
  const observedIso = observedAt.toISOString();
  const freshness = freshnessFor(DNS_SOURCE_DESCRIPTOR.freshness, observedAt, null);

  // TTL is neutral evidence data, not an outcome-freshness assertion: a live DNS
  // snapshot has no honest expiry, but the minimum record TTL and its derived
  // expiry instant are recorded so a caller can reason about record lifetime.
  const recordsExpireAt =
    state.minTtlSeconds !== null
      ? new Date(observedAt.getTime() + state.minTtlSeconds * 1000).toISOString()
      : null;

  const evidence: EnrichmentEvidence = {
    type: DNS_RECORDS_EVIDENCE_TYPE,
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      host: state.host,
      zone: state.zone,
      resolvable: state.resolvable,
      mailSemantic: state.mailSemantic,
      a: { state: state.a.state, addresses: [...state.a.addresses], ttlSeconds: state.a.ttlSeconds },
      aaaa: {
        state: state.aaaa.state,
        addresses: [...state.aaaa.addresses],
        ttlSeconds: state.aaaa.ttlSeconds,
      },
      ns: { state: state.ns.state, hosts: [...state.ns.hosts], ttlSeconds: state.ns.ttlSeconds },
      mx: {
        state: state.mx.state,
        exchanges: state.mx.exchanges.map((e) => ({ exchange: e.exchange, preference: e.preference })),
        ttlSeconds: state.mx.ttlSeconds,
      },
      minTtlSeconds: state.minTtlSeconds,
      recordsExpireAt,
    },
  };

  // A second attributed artifact for the zone's DNSSEC validation state. This is
  // neutral evidence: `insecure`/absence is NOT risk, and even `bogus` is only an
  // anomaly (often a misconfiguration), so it is recorded — never scored. When the
  // state could not be determined it is faithfully `indeterminate`; that does not
  // fail the outcome, because the DNS records were still authoritatively observed.
  const dnssecEvidence: EnrichmentEvidence = {
    type: DNS_DNSSEC_EVIDENCE_TYPE,
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      name: dnssec.name,
      validationState: dnssec.state,
      resolverValidates: dnssec.resolverValidates,
      ...(dnssec.unresolved !== undefined ? { unresolved: dnssec.unresolved } : {}),
    },
  };

  // Evidence-only: DNS state (records + DNSSEC) is neutral, so no finding is ever
  // projected — not even for a `bogus` DNSSEC verdict.
  return {
    sourceId: DNS_SOURCE_ID,
    layer: "reputation",
    status: "success",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    evidence: [evidence, dnssecEvidence],
    findings: [],
  };
}

interface Disposition {
  readonly status: "skipped" | "failure";
  readonly code: string;
  readonly reason: DnsUnresolvedState;
  readonly retryable: boolean;
}

const UNRESOLVED_PRIORITY: readonly DnsUnresolvedState[] = [
  "aborted",
  "timeout",
  "refused",
  "servfail",
  "error",
];

/**
 * Choose the dispositive failure across the four unresolved answers. Cancellation
 * and timeout are transient `skipped` non-results; a server failure, refusal, or
 * unexpected error is a `failure`. Priority favors the most caller-actionable
 * reason (abort/timeout) over server-side ones.
 */
function dominantFailure(answers: readonly DnsAnswer[]): Disposition {
  const seen = new Set(answers.map((answer) => answer.state));
  const reason = UNRESOLVED_PRIORITY.find((candidate) => seen.has(candidate)) ?? "error";
  switch (reason) {
    case "aborted":
      return { status: "skipped", code: "dns-caller-aborted", reason, retryable: true };
    case "timeout":
      return { status: "skipped", code: "dns-timeout", reason, retryable: true };
    case "refused":
      return { status: "failure", code: "dns-refused", reason, retryable: true };
    case "servfail":
      return { status: "failure", code: "dns-servfail", reason, retryable: true };
    case "error":
      return { status: "failure", code: "dns-resolver-error", reason, retryable: true };
  }
}

function degradedOutcome(
  status: "skipped" | "failure",
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return {
    sourceId: DNS_SOURCE_ID,
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

function signalOpt(signal: AbortSignal | undefined): { signal?: AbortSignal } {
  return signal !== undefined ? { signal } : {};
}

function provenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: { name: DNS_SOURCE_ID, version: DNS_SOURCE_VERSION },
    data: { name: "dns.resolver" },
  };
}

function report(outcome: EnrichmentOutcome): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes: [outcome] };
}
