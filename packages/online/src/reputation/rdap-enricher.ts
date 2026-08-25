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

import {
  assertSourceTermsAccepted,
  freshnessFor,
  type SourceTermsAcceptance,
} from "../sources/index.js";
import { fetchRdapDomain, RDAP_SOURCE_ID, RDAP_SOURCE_VERSION } from "./rdap-client.js";
import { RDAP_SOURCE_DESCRIPTOR } from "./rdap-descriptor.js";
import type {
  RdapBootstrapRegistry,
  RdapBootstrapSnapshot,
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
  /**
   * The caller's acceptance of this source's licensing terms. REQUIRED: the
   * source is constructed only under terms it can honor, so there is no default
   * to fall back to. `assertSourceTermsAccepted` checks them against
   * `RDAP_SOURCE_DESCRIPTOR.terms` before the enricher exists.
   */
  readonly terms: SourceTermsAcceptance;
  /** Provider-scoped RDAP HTTP client (deterministic fixture in tests). */
  readonly client: RdapHttpClient;
  /**
   * IANA DNS bootstrap data used for authoritative routing. Three shapes, all
   * explicit:
   *
   * - {@link RdapBootstrapSnapshot} — the preferred form, produced by
   *   `updateRdapBootstrap`. Its metadata carries an `expiresAt`, so an
   *   out-of-date routing table becomes an answerable question rather than an
   *   invisible one; past that instant every lookup is `skipped` with
   *   `rdap-bootstrap-stale`.
   * - {@link RdapBootstrapRegistry} — a bare registry, the pre-LINK-mkddydzr
   *   form. Kept for callers that already own one; it carries no freshness at
   *   all, so nothing here can claim any, and it is never treated as stale.
   * - `null` — the caller has no bootstrap data (no snapshot stored yet, or the
   *   last update failed). Every lookup is `skipped` with
   *   `rdap-bootstrap-unavailable`. This is the explicit missing-data state: the
   *   enricher never guesses a base URL and never silently falls back.
   */
  readonly registry: RdapBootstrapSnapshot | RdapBootstrapRegistry | null;
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
  // Terms first: nothing else in this factory runs under terms RDAP cannot
  // honor. RDAP supports every commercial mode and requires no attribution,
  // so no legal `terms` value refuses here today — the argument is required
  // so the "never constructed under terms it cannot honor" claim is true of
  // every call, and stays true if the descriptor ever tightens.
  assertSourceTermsAccepted(RDAP_SOURCE_DESCRIPTOR, options.terms);

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

      // Bootstrap availability and freshness are decided BEFORE any lookup: a
      // missing or expired routing table is an explicit skip with a
      // machine-readable cause, never a guessed endpoint.
      const bootstrap = resolveBootstrap(options.registry, observedAt);
      if (bootstrap.status !== "usable") {
        return report(skippedOutcome(subject, observedAt, bootstrap.cause));
      }

      const fetchOptions = {
        client: options.client,
        registry: bootstrap.registry,
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

interface EnricherCause {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: EnrichmentCause["details"];
}

type BootstrapResolution =
  | { readonly status: "usable"; readonly registry: RdapBootstrapRegistry }
  | { readonly status: "unusable"; readonly cause: EnricherCause };

/**
 * Decide whether the caller's bootstrap data may route a lookup.
 *
 * The two forms are discriminated structurally: a snapshot has a `registry`
 * field, the bare registry has `services`. A snapshot is checked against its own
 * `expiresAt`; a bare registry has no freshness to check, so it is used as
 * given rather than having a fabricated one attributed to it.
 *
 * Staleness is a skip rather than a downgrade because a stale bootstrap is not
 * merely old data — it is a routing table that may point a query at an endpoint
 * that is no longer authoritative for the TLD.
 */
function resolveBootstrap(
  bootstrap: RdapBootstrapSnapshot | RdapBootstrapRegistry | null,
  now: Date,
): BootstrapResolution {
  if (bootstrap === null) {
    return {
      status: "unusable",
      cause: {
        code: "rdap-bootstrap-unavailable",
        message: "no IANA bootstrap registry is available to route the query",
        // Retryable: acquiring a snapshot is exactly what makes this succeed.
        retryable: true,
      },
    };
  }

  if (!("registry" in bootstrap)) return { status: "usable", registry: bootstrap };

  const expiresAt = bootstrap.metadata.expiresAt;
  if (expiresAt !== null) {
    const expiry = Date.parse(expiresAt);
    if (Number.isFinite(expiry) && now.getTime() >= expiry) {
      return {
        status: "unusable",
        cause: {
          code: "rdap-bootstrap-stale",
          message: "the stored IANA bootstrap registry expired and may misroute the query",
          retryable: true,
          details: { observedAt: bootstrap.metadata.observedAt, expiresAt },
        },
      };
    }
  }
  return { status: "usable", registry: bootstrap.registry };
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
