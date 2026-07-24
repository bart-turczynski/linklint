/**
 * URLhaus exact-URL lookup enricher and reputation finding (LINK-ifpdilfn, M4b).
 *
 * Wraps a caller-owned URLhaus snapshot as a core {@link Enricher}. At check time
 * it looks the inspected URL up in a locally-held snapshot index — **no network
 * I/O** — and, on an exact match, emits a source-attributed `urlhaus.match`
 * evidence artifact. A scored `malware_url_listed` finding is projected ONLY when
 * the matched record is currently listed online AND the snapshot is within its
 * declared freshness: an authoritative, subject-tied, within-freshness match.
 *
 * URLhaus covers direct malware-distribution URLs, not phishing or general domain
 * reputation, and the lookup is exact-URL only (never broadened to the host), so
 * an offline/expired record or a stale snapshot stays evidence-only, a
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

import { freshnessFor } from "../sources/index.js";
import { canonicalizeUrl } from "./urlhaus-index.js";
import {
  URLHAUS_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_ID,
  URLHAUS_SOURCE_VERSION,
} from "./urlhaus-descriptor.js";
import type { UrlhausIndex, UrlhausRecord } from "./types.js";

export interface UrlhausEnricherOptions {
  /**
   * Resolves the current caller-owned snapshot index, or `null` when no snapshot
   * is loaded yet. Called once per check so a caller can swap in a freshly-updated
   * snapshot between inspections without rebuilding the enricher. It MUST NOT
   * perform network I/O — refreshing the snapshot is the M4a updater's job.
   */
  readonly resolveIndex: () => UrlhausIndex | null;
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
}

/**
 * Build the URLhaus exact-URL lookup enricher. It queries the inspected URL
 * against the current local snapshot, emits `urlhaus.match` evidence on a hit, and
 * projects a `malware_url_listed` finding for an online match within a fresh
 * snapshot.
 */
export function createUrlhausEnricher(options: UrlhausEnricherOptions): Enricher {
  const now = options.now ?? (() => new Date());

  return {
    id: URLHAUS_SOURCE_ID,
    layer: "reputation",
    enrich(result: InspectResult): Promise<EnrichmentReport> {
      const observedAt = now();
      const subject: EnrichmentSubject = { kind: "url", value: result.input };
      const index = options.resolveIndex();

      if (index === null) {
        return done(
          skippedOutcome(subject, observedAt, {
            code: "urlhaus-no-snapshot",
            message: "no URLhaus snapshot is loaded",
            retryable: true,
          }),
        );
      }

      // A non-http(s) or unparseable input can never match a URL feed.
      if (canonicalizeUrl(result.input) === null) {
        return done(
          skippedOutcome(subject, observedAt, {
            code: "urlhaus-uncanonicalizable-input",
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
  record: UrlhausRecord,
  index: UrlhausIndex,
): EnrichmentOutcome {
  const observedIso = observedAt.toISOString();
  const evidence: EnrichmentEvidence = {
    type: "urlhaus.match",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      url: record.url,
      recordId: record.id,
      status: record.status,
      threat: record.threat,
      tags: [...record.tags],
      dateAdded: record.dateAdded,
      lastOnline: record.lastOnline,
      reporter: record.reporter,
      snapshotObservedAt: index.metadata.observedAt,
    },
  };

  // Conjunctive gate: an exact match scores only when the record is live AND the
  // snapshot is fresh. An offline/expired record or a stale/unknown snapshot is
  // evidence, not a finding.
  const eligible = record.status === "online" && freshness.status === "fresh";
  const findings = eligible
    ? [
        {
          code: "malware_url_listed" as const,
          detail:
            `exact URL match in the URLhaus snapshot: ${record.url} is listed online as ` +
            `${record.threat ?? "malware"} (record ${record.id})`,
          confidence: 0.95,
        },
      ]
    : [];

  return {
    sourceId: URLHAUS_SOURCE_ID,
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
    sourceId: URLHAUS_SOURCE_ID,
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
    sourceId: URLHAUS_SOURCE_ID,
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

function snapshotFreshness(index: UrlhausIndex, observedAt: Date): EnrichmentFreshness {
  const expiresAt =
    index.metadata.expiresAt !== null ? new Date(index.metadata.expiresAt) : null;
  return freshnessFor(URLHAUS_SOURCE_DESCRIPTOR.freshness, observedAt, expiresAt);
}

function provenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: { name: URLHAUS_SOURCE_ID, version: URLHAUS_SOURCE_VERSION },
    data: { name: "urlhaus.abuse.ch" },
  };
}

function done(outcome: EnrichmentOutcome): Promise<EnrichmentReport> {
  return Promise.resolve({ schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes: [outcome] });
}
