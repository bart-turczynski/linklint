/**
 * PhishTank exact-URL lookup enricher and reputation finding (LINK-unqxyfce, M5b).
 *
 * Wraps a caller-owned PhishTank snapshot as a core {@link Enricher}. At check
 * time it looks the inspected URL up in a locally-held snapshot index — **no
 * network I/O** — and, on an exact match, emits a source-attributed
 * `phishtank.match` evidence artifact preserving PhishTank's verification,
 * validity, target, and observation timestamps. A scored `verified_phish_listed`
 * finding is projected ONLY when the matched record is human-verified AND
 * currently online AND the snapshot is within its declared freshness.
 *
 * The lookup is exact-URL only (never broadened to the host), so an unverified,
 * offline, or removed record, or a stale snapshot, stays evidence-only, a
 * path/query mismatch is a `no-hit`, and a miss is never a safety claim.
 */

import {
  ENRICHMENT_SCHEMA_VERSION,
  type Enricher,
  type EnrichmentCause,
  type EnrichmentEvidence,
  type EnrichmentFreshness,
  type EnrichmentOutcome,
  type EnrichmentProvenance,
  type EnrichmentReport,
  type EnrichmentSubject,
  type InspectResult,
} from "linklint";

import {
  assertSourceTermsAccepted,
  freshnessFor,
  type SourceTermsAcceptance,
} from "../sources/index.js";
import { canonicalizeUrl } from "./url-canonical.js";
import {
  PHISHTANK_SOURCE_DESCRIPTOR,
  PHISHTANK_SOURCE_ID,
  PHISHTANK_SOURCE_VERSION,
} from "./phishtank-descriptor.js";
import type { PhishTankIndex, PhishTankRecord } from "./phishtank-types.js";

export interface PhishTankEnricherOptions {
  /**
   * The caller's acceptance of this source's licensing terms. REQUIRED: the
   * source is constructed only under terms it can honor, so there is no default
   * to fall back to. `assertSourceTermsAccepted` checks them against
   * `PHISHTANK_SOURCE_DESCRIPTOR.terms` before the enricher exists.
   */
  readonly terms: SourceTermsAcceptance;
  /**
   * Resolves the current caller-owned snapshot index, or `null` when no snapshot
   * is loaded. Called once per check so a caller can swap in a freshly-updated
   * snapshot between inspections. It MUST NOT perform network I/O — refreshing
   * the snapshot is the M5a updater's job.
   */
  readonly resolveIndex: () => PhishTankIndex | null;
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
}

/**
 * Build the PhishTank exact-URL lookup enricher. It queries the inspected URL
 * against the current local snapshot, emits `phishtank.match` evidence on a hit,
 * and projects a `verified_phish_listed` finding for a verified, online match
 * within a fresh snapshot.
 */
export function createPhishTankEnricher(options: PhishTankEnricherOptions): Enricher {
  // Terms first, and here the gate genuinely refuses: PhishTank grants free
  // use WITH attribution and assumes no commercial grant, so `commercialMode:
  // "commercial"` and a declined attribution both throw before an enricher
  // exists. No feed credential is asked for — the app key is revealed only by
  // the M5a updater, in the download URL path.
  assertSourceTermsAccepted(PHISHTANK_SOURCE_DESCRIPTOR, options.terms);

  const now = options.now ?? (() => new Date());

  return {
    id: PHISHTANK_SOURCE_ID,
    layer: "reputation",
    enrich(result: InspectResult): Promise<EnrichmentReport> {
      const observedAt = now();
      const subject: EnrichmentSubject = { kind: "url", value: result.input };
      const index = options.resolveIndex();

      if (index === null) {
        return done(
          skippedOutcome(subject, observedAt, {
            code: "phishtank-no-snapshot",
            message: "no PhishTank snapshot is loaded",
            retryable: true,
          }),
        );
      }

      if (canonicalizeUrl(result.input) === null) {
        return done(
          skippedOutcome(subject, observedAt, {
            code: "phishtank-uncanonicalizable-input",
            message: "input is not an absolute http(s) URL",
            retryable: false,
          }),
        );
      }

      const freshness = snapshotFreshness(index, observedAt);
      const record = index.lookup(result.input);

      if (record === null) {
        return done(noHitOutcome(subject, observedAt, freshness));
      }
      return done(matchOutcome(subject, observedAt, freshness, record, index));
    },
  };
}

function matchOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  freshness: EnrichmentFreshness,
  record: PhishTankRecord,
  index: PhishTankIndex,
): EnrichmentOutcome {
  const observedIso = observedAt.toISOString();
  const evidence: EnrichmentEvidence = {
    type: "phishtank.match",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      url: record.url,
      phishId: record.phishId,
      detailUrl: record.detailUrl,
      verified: record.verified,
      verificationTime: record.verificationTime,
      submissionTime: record.submissionTime,
      online: record.online,
      target: record.target,
      snapshotObservedAt: index.metadata.observedAt,
    },
  };

  // Conjunctive gate: an exact match scores only when the record is human-verified
  // AND live AND the snapshot is fresh. Unverified/offline/removed records or a
  // stale snapshot are evidence, not a finding.
  const eligible = record.verified && record.online && freshness.status === "fresh";
  const findings = eligible
    ? [
        {
          code: "verified_phish_listed" as const,
          detail:
            `exact URL match in the PhishTank snapshot: ${record.url} is a verified, online ` +
            `phish targeting ${record.target ?? "an unspecified brand"} (phish ${record.phishId})`,
          confidence: 0.95,
        },
      ]
    : [];

  return {
    sourceId: PHISHTANK_SOURCE_ID,
    layer: "reputation",
    status: "success",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    evidence: [evidence],
    findings,
  };
}

function noHitOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  freshness: EnrichmentFreshness,
): EnrichmentOutcome {
  return {
    sourceId: PHISHTANK_SOURCE_ID,
    layer: "reputation",
    status: "no-hit",
    subject,
    observedAt: observedAt.toISOString(),
    provenance: provenance(),
    freshness,
    evidence: [],
    findings: [],
  };
}

function skippedOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return {
    sourceId: PHISHTANK_SOURCE_ID,
    layer: "reputation",
    status: "skipped",
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

function snapshotFreshness(index: PhishTankIndex, observedAt: Date): EnrichmentFreshness {
  const expiresAt =
    index.metadata.expiresAt !== null ? new Date(index.metadata.expiresAt) : null;
  return freshnessFor(PHISHTANK_SOURCE_DESCRIPTOR.freshness, observedAt, expiresAt);
}

function provenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: { name: PHISHTANK_SOURCE_ID, version: PHISHTANK_SOURCE_VERSION },
    data: { name: "phishtank" },
  };
}

function done(outcome: EnrichmentOutcome): Promise<EnrichmentReport> {
  return Promise.resolve({ schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes: [outcome] });
}
