/**
 * RDAP domain-age enricher and conjunctive reputation finding (LINK-brykoojd, M1b).
 *
 * Wraps the M1a source client as a core {@link Enricher}. Every completed lookup
 * emits a source-attributed `rdap.domain` evidence artifact (registration and
 * last-changed dates, registrar, nameservers, DNSSEC, redaction, and the
 * computed age). A scored `young_domain_brand_risk` finding is projected ONLY
 * when two independent axes agree: the ICANN registrable domain's age is below
 * the young-domain threshold AND the lexical result already carries a
 * brand-impersonation reason. Age alone — like registrar, nameservers, or
 * country — is evidence, never proof.
 *
 * Age is computed on the registrable domain, so a phishing subdomain under an
 * ancient shared-hosting parent inherits the parent's age and never reads young.
 * Missing or redacted registration events remain unknown and fabricate nothing.
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
import { fetchRdapDomain, RDAP_SOURCE_ID, RDAP_SOURCE_VERSION } from "./rdap-client.js";
import { RDAP_SOURCE_DESCRIPTOR } from "./rdap-descriptor.js";
import type {
  RdapBootstrapRegistry,
  RdapCache,
  RdapDomainRecord,
  RdapFetchResult,
  RdapHttpClient,
} from "./types.js";

/** Default young-domain threshold, in days. A registrable domain strictly younger
 * than this is "young"; exactly this age or older is not. */
export const DEFAULT_YOUNG_DOMAIN_THRESHOLD_DAYS = 90;

/**
 * Lexical brand-impersonation reason codes that corroborate a young domain. Each
 * is a registrable-domain-scoped brand signal, so both axes describe the same
 * subject. `young_domain_brand_risk` fires only when a non-suppressed member of
 * this set is present.
 */
export const RDAP_BRAND_CORROBORATION_CODES: readonly string[] = [
  "brand_homoglyph",
  "homograph_skeleton_collision",
  "homograph_latin_skeleton",
  "api_endpoint_impersonation",
];

const MS_PER_DAY = 86_400_000;

export interface RdapAgeEnricherOptions {
  /** Provider-scoped RDAP HTTP client (deterministic fixture in tests). */
  readonly client: RdapHttpClient;
  /** IANA DNS bootstrap registry used for authoritative routing. */
  readonly registry: RdapBootstrapRegistry;
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
  /** Optional read-through record cache. */
  readonly cache?: RdapCache;
  /** Record lifetime, in ms, used to derive freshness/expiry. */
  readonly cacheTtlMs?: number;
  /** Young-domain threshold in days. Invalid values retain the safe default. */
  readonly youngThresholdDays?: number;
  /** Override the corroborating lexical brand code set. */
  readonly corroboratingCodes?: readonly string[];
  /** Maximum RDAP redirects to follow. */
  readonly maxRedirects?: number;
}

/**
 * Build the RDAP registration-age enricher. It queries the registrable domain,
 * emits evidence, and conjoins a young age with a lexical brand signal into a
 * single scored finding.
 */
export function createRdapAgeEnricher(options: RdapAgeEnricherOptions): Enricher {
  const now = options.now ?? (() => new Date());
  const thresholdDays = boundedThreshold(options.youngThresholdDays);
  const corroborating = new Set(options.corroboratingCodes ?? RDAP_BRAND_CORROBORATION_CODES);

  return {
    id: RDAP_SOURCE_ID,
    layer: "reputation",
    async enrich(result: InspectResult): Promise<EnrichmentReport> {
      const registrableDomain = result.parsed?.registrableDomain ?? null;
      const subject = subjectFor(result, registrableDomain);
      const observedAt = now();

      if (registrableDomain === null) {
        return report(
          skippedOutcome(subject, observedAt, {
            code: "rdap-no-registrable-domain",
            message: "input has no registrable domain to query",
            retryable: false,
          }),
        );
      }

      const fetchOptions = {
        client: options.client,
        registry: options.registry,
        registrableDomain,
        clock: { now },
        ...(options.cache ? { cache: options.cache } : {}),
        ...(options.cacheTtlMs !== undefined ? { cacheTtlMs: options.cacheTtlMs } : {}),
        ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
      };
      const lookup: RdapFetchResult = await fetchRdapDomain(fetchOptions);

      switch (lookup.status) {
        case "found":
          return report(
            foundOutcome(subject, lookup.record, {
              observedAt,
              thresholdDays,
              corroborated: hasCorroboratingBrandSignal(result, corroborating),
            }),
          );
        case "no-hit":
          return report(noHitOutcome(subject, observedAt));
        case "skipped":
          return report(skippedOutcome(subject, observedAt, lookup.cause));
        case "failure":
          return report(failureOutcome(subject, observedAt, lookup.cause));
      }
    },
  };
}

interface FoundContext {
  readonly observedAt: Date;
  readonly thresholdDays: number;
  readonly corroborated: boolean;
}

function foundOutcome(
  subject: EnrichmentSubject,
  record: RdapDomainRecord,
  ctx: FoundContext,
): EnrichmentOutcome {
  const ageDays = ageInDays(record.registrationDate, ctx.observedAt);
  const young = ageDays !== null && ageDays < ctx.thresholdDays;
  const expiresAt = record.expiresAt !== null ? new Date(record.expiresAt) : null;
  const freshness = freshnessFor(RDAP_SOURCE_DESCRIPTOR.freshness, ctx.observedAt, expiresAt);
  const observedIso = ctx.observedAt.toISOString();

  const evidence: EnrichmentEvidence = {
    type: "rdap.domain",
    subject,
    observedAt: observedIso,
    provenance: provenance(),
    freshness,
    payload: {
      domain: record.domain,
      registrationDate: record.registrationDate,
      lastChangedDate: record.lastChangedDate,
      expirationDate: record.expirationDate,
      ageDays,
      registrar: record.registrar?.name ?? null,
      registrarHandle: record.registrar?.handle ?? null,
      nameserverCount: record.nameservers.length,
      delegationSigned: record.delegationSigned,
      statuses: [...record.statuses],
      redacted: [...record.redacted],
    },
  };

  // The conjunctive finding fires only when BOTH axes agree on the same subject.
  const findings =
    young && ctx.corroborated
      ? [
          {
            code: "young_domain_brand_risk" as const,
            detail:
              `registrable domain ${record.domain} was registered ${ageDays}d ago ` +
              `(< ${ctx.thresholdDays}d) and carries a lexical brand-impersonation signal`,
            confidence: 0.9,
          },
        ]
      : [];

  return {
    sourceId: RDAP_SOURCE_ID,
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

function noHitOutcome(subject: EnrichmentSubject, observedAt: Date): EnrichmentOutcome {
  return {
    sourceId: RDAP_SOURCE_ID,
    layer: "reputation",
    status: "no-hit",
    subject,
    observedAt: observedAt.toISOString(),
    provenance: provenance(),
    freshness: { status: "unknown", expiresAt: null },
    evidence: [],
    findings: [],
  };
}

function skippedOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return degraded("skipped", subject, observedAt, cause);
}

function failureOutcome(
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return degraded("failure", subject, observedAt, cause);
}

function degraded(
  status: "skipped" | "failure",
  subject: EnrichmentSubject,
  observedAt: Date,
  cause: { code: string; message: string; retryable: boolean; details?: EnrichmentCause["details"] },
): EnrichmentOutcome {
  return {
    sourceId: RDAP_SOURCE_ID,
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

/** Whole days between a registration instant and now, or `null` when unknown. */
function ageInDays(registrationDate: string | null, now: Date): number | null {
  if (registrationDate === null) return null;
  const registered = Date.parse(registrationDate);
  if (!Number.isFinite(registered)) return null;
  const deltaMs = now.getTime() - registered;
  if (deltaMs < 0) return 0; // a future registration date is treated as age 0, never negative
  return Math.floor(deltaMs / MS_PER_DAY);
}

function hasCorroboratingBrandSignal(
  result: InspectResult,
  corroborating: ReadonlySet<string>,
): boolean {
  return result.reasons.some(
    (reason) => corroborating.has(reason.code) && reason.suppressed !== true,
  );
}

function subjectFor(result: InspectResult, registrableDomain: string | null): EnrichmentSubject {
  if (registrableDomain !== null) return { kind: "host", value: registrableDomain };
  const host = result.parsed?.effectiveHost;
  if (typeof host === "string" && host !== "") return { kind: "host", value: host };
  return { kind: "url", value: result.input };
}

function provenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: { name: RDAP_SOURCE_ID, version: RDAP_SOURCE_VERSION },
    data: { name: "rdap.authoritative-registry" },
  };
}

function report(outcome: EnrichmentOutcome): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes: [outcome] };
}

function boundedThreshold(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return DEFAULT_YOUNG_DOMAIN_THRESHOLD_DAYS;
  }
  return Math.floor(value);
}
