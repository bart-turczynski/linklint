import {
  ENRICHMENT_SCHEMA_VERSION,
  inspect,
  type EnrichmentEvidence,
  type EnrichmentFreshness,
  type EnrichmentOutcome,
  type EnrichmentPayload,
  type EnrichmentProvenance,
  type EnrichmentReport,
} from "linklint";

import type {
  SafeFetchOutcome,
  SafeFetchResponse,
  SafeTransportSession,
  TransportEvidence,
  TransportMethod,
} from "../transport/types.js";
import type {
  DivergenceProbeAuthorizationRequest,
  DivergenceProbeEnricher,
  DivergenceProbeEnricherOptions,
  DivergenceProbeVariant,
  DivergenceProbeVariantSummary,
} from "./types.js";
import { sniffMimeType } from "./mime-sniff.js";

export const DIVERGENCE_PROBE_SOURCE_ID = "divergence-probe.http" as const;
export const DIVERGENCE_PROBE_SOURCE_VERSION = "1.0.0" as const;
export const DEFAULT_DIVERGENCE_PROBE_MAX_BODY_BYTES = 65_536;

const MAX_DIVERGENCE_PROBE_BODY_BYTES = 1_048_576;
const MAX_PROBE_URL_LENGTH = 16_384;
const FRESHNESS: EnrichmentFreshness = { status: "fresh", expiresAt: null };

/**
 * Controlled, synthetic User-Agent used for the alternate variant. It is a fixed
 * benign desktop-Chrome string chosen only to surface UA-conditioned responses;
 * it impersonates no caller and is never derived from ambient request state.
 */
const ALT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";

/**
 * The fixed, bounded default variant set: three variants → three single
 * fetches, each separately authorized. The set varies exactly two controlled
 * dimensions against the same baseline — User-Agent, and absent vs synthetic
 * same-origin Referer.
 */
export const DEFAULT_DIVERGENCE_VARIANTS: readonly DivergenceProbeVariant[] = [
  { label: "baseline", headers: {} },
  { label: "alt-user-agent", headers: { "user-agent": ALT_USER_AGENT } },
  { label: "same-origin-referer", headers: {}, referer: "same-origin-root" },
];

/** Dimensions compared for divergence across successful variant summaries. */
const DIVERGENCE_DIMENSIONS = [
  "statusClass",
  "location",
  "declaredEssence",
  "computedEssence",
] as const;

type DivergenceDimension = (typeof DIVERGENCE_DIMENSIONS)[number];

/**
 * Fixed challenge/CAPTCHA/JS-gate marker table. Substring match is
 * case-insensitive; the first matching id wins. A match makes resolution
 * explicitly INCOMPLETE for that variant — never a false clean.
 */
const CHALLENGE_MARKERS: readonly { readonly id: string; readonly needles: readonly string[] }[] = [
  {
    id: "cloudflare-challenge",
    needles: ["cf-chl", "cf-mitigated", "just a moment...", "challenge-platform"],
  },
  { id: "recaptcha", needles: ["g-recaptcha", "recaptcha/api.js"] },
  { id: "hcaptcha", needles: ["h-captcha", "hcaptcha.com/1/api.js"] },
];

/**
 * Build an explicitly authorized L4 controlled-variant divergence probe. One L0
 * session is retained for the whole probe so transport budgets stay cumulative
 * across the bounded variant set. Divergence is emitted as EVIDENCE ONLY: no
 * finding, no score, never an independently scored cloaking claim. A challenge
 * gate degrades that variant to an explicit resolution-incomplete outcome.
 *
 * The comparison observes a two-sample floor. `resolution.divergence` reports
 * `divergent: null` when fewer than two variants were successfully sampled,
 * because a verdict of `false` off zero or one sample says "compared and agreed"
 * about a comparison that never happened.
 */
export function createDivergenceProbeEnricher(
  options: DivergenceProbeEnricherOptions,
): DivergenceProbeEnricher {
  const method = options.method === "HEAD" ? "HEAD" : "GET";
  const variants = options.variants ?? DEFAULT_DIVERGENCE_VARIANTS;
  const maxBodyBytes = boundedInteger(
    options.maxBodyBytes,
    DEFAULT_DIVERGENCE_PROBE_MAX_BODY_BYTES,
    MAX_DIVERGENCE_PROBE_BODY_BYTES,
  );
  const inspectOptions = options.inspectOptions ?? {};
  const now = options.now ?? (() => new Date());

  return {
    id: DIVERGENCE_PROBE_SOURCE_ID,
    layer: "resolution",
    async enrich(base, context): Promise<EnrichmentReport> {
      const url = canonicalHttpUrl(base.input);
      if (url === null) {
        return report([
          degradationOutcome(
            base.input,
            observedInstant(now),
            "failure",
            "invalid-target",
            false,
          ),
        ]);
      }

      const session = options.transport.createSession();
      const outcomes: EnrichmentOutcome[] = [];
      const successfulSummaries: DivergenceProbeVariantSummary[] = [];

      for (let index = 0; index < variants.length; index += 1) {
        const variant = variants[index]!;
        const hop = index + 1;

        let authorization;
        try {
          const request: DivergenceProbeAuthorizationRequest = {
            url,
            hop,
            method,
            reason: "variant-probe",
            variant: variant.label,
          };
          authorization = await options.authorize(request);
        } catch {
          outcomes.push(
            degradationOutcome(url, observedInstant(now), "failure", "authorization-error", false, {
              variant: variant.label,
            }),
          );
          continue;
        }
        if (authorization === null) {
          outcomes.push(
            degradationOutcome(url, observedInstant(now), "skipped", "authorization-denied", false, {
              variant: variant.label,
              hop,
            }),
          );
          continue;
        }

        const referer = variantReferer(url, variant);
        const fetched = await fetchVariant(
          session,
          url,
          authorization,
          method,
          variant,
          referer,
          context,
        );
        if (fetched.status !== "success") {
          outcomes.push(transportDegradation(fetched, variant.label));
          continue;
        }

        const summary = summarize(
          variant.label,
          referer,
          fetched.response,
          url,
          method,
          maxBodyBytes,
          (value) => inspect(value, inspectOptions).parsed?.registrableDomain ?? null,
        );
        if (summary.challenge !== null) {
          outcomes.push(challengeOutcome(url, fetched.observedAt, summary));
          continue;
        }
        successfulSummaries.push(summary);
        outcomes.push(variantOutcome(url, fetched.observedAt, summary));
      }

      outcomes.push(divergenceOutcome(base.input, observedInstant(now), successfulSummaries));
      return report(outcomes);
    },
  };
}

/**
 * Derive the synthetic Referer for a variant from the probed URL alone. The
 * origin root is the only value this probe ever sends: it carries nothing the
 * destination does not already know about the request, so no private or
 * user-derived referrer can exist to leak. L0 independently re-validates it.
 */
function variantReferer(url: string, variant: DivergenceProbeVariant): string | null {
  if (variant.referer !== "same-origin-root") return null;
  try {
    return new URL(url).origin + "/";
  } catch {
    return null;
  }
}

async function fetchVariant(
  session: SafeTransportSession,
  url: string,
  authorization: { readonly kind: "destination-fetch"; readonly url: string },
  method: TransportMethod,
  variant: DivergenceProbeVariant,
  referer: string | null,
  context: { readonly signal?: AbortSignal },
): Promise<SafeFetchOutcome> {
  return session.fetch({
    url,
    authorization,
    method,
    ...(Object.keys(variant.headers).length === 0 ? {} : { headers: variant.headers }),
    ...(referer === null ? {} : { sameOriginReferer: referer }),
    ...(context.signal === undefined ? {} : { signal: context.signal }),
  });
}

function summarize(
  label: string,
  referer: string | null,
  response: SafeFetchResponse,
  requestUrl: string,
  method: TransportMethod,
  maxBodyBytes: number,
  registrableDomainOf: (value: string) => string | null,
): DivergenceProbeVariantSummary {
  const statusClass = Math.floor(response.status / 100);
  const declared = singleHeaderValue(response.headers, "content-type");
  const prefix = response.body.subarray(0, maxBodyBytes);
  const bodyPresent = method !== "HEAD" && prefix.byteLength > 0;

  const declaredEssence = sniffMimeType(bodyPresent ? prefix : EMPTY_PREFIX, declared).declaredEssence;
  const computedEssence = bodyPresent ? sniffMimeType(prefix, declared).computedEssence : null;
  const challenge = bodyPresent ? detectChallenge(prefix) : null;
  const location =
    statusClass === 3 ? locationRegistrableDomain(response, requestUrl, registrableDomainOf) : null;

  return {
    label,
    referer,
    status: response.status,
    statusClass,
    location,
    declaredEssence,
    computedEssence,
    challenge,
  };
}

const EMPTY_PREFIX = new Uint8Array(0);

function detectChallenge(prefix: Uint8Array): string | null {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(prefix).toLowerCase();
  for (const marker of CHALLENGE_MARKERS) {
    if (marker.needles.some((needle) => text.includes(needle))) return marker.id;
  }
  return null;
}

function locationRegistrableDomain(
  response: SafeFetchResponse,
  requestUrl: string,
  registrableDomainOf: (value: string) => string | null,
): string | null {
  const location = singleHeaderValue(response.headers, "location");
  if (location === null) return null;
  let absolute: string;
  try {
    absolute = new URL(location, requestUrl).href;
  } catch {
    return null;
  }
  return registrableDomainOf(absolute);
}

function variantOutcome(
  url: string,
  observedAt: string,
  summary: DivergenceProbeVariantSummary,
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: url };
  const provenance = declaredProvenance();
  return {
    sourceId: DIVERGENCE_PROBE_SOURCE_ID,
    layer: "resolution",
    status: "success",
    subject,
    observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence: [
      {
        type: "resolution.variant-response",
        subject,
        observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: { ...summary },
      },
    ],
    findings: [],
  };
}

function challengeOutcome(
  url: string,
  observedAt: string,
  summary: DivergenceProbeVariantSummary,
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: url };
  const provenance = declaredProvenance();
  return {
    sourceId: DIVERGENCE_PROBE_SOURCE_ID,
    layer: "resolution",
    status: "skipped",
    subject,
    observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence: [
      {
        type: "resolution.challenge",
        subject,
        observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: {
          variant: summary.label,
          marker: summary.challenge,
          status: summary.status,
        },
      },
    ],
    findings: [],
    cause: {
      code: "challenge-gate",
      retryable: false,
      details: { variant: summary.label, marker: summary.challenge },
    },
  };
}

function divergenceOutcome(
  input: string,
  observedAt: string,
  summaries: readonly DivergenceProbeVariantSummary[],
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: input };
  const provenance = declaredProvenance();
  // Comparing needs two samples. Below that there is no observation to report,
  // so `divergent` is null rather than false: `false` is a claim that variants
  // were compared and agreed, and emitting it off zero or one sample turns a
  // transport fault into "no divergence observed" (LINK-oevpffva). Null is the
  // conservative spelling — a consumer testing `payload.divergent` truthily
  // reads it as "no divergence claim", while `=== false` correctly stops
  // matching the degenerate case it used to match silently.
  const comparable = summaries.length >= 2;
  const divergentDimensions = comparable ? divergentAmong(summaries) : [];
  return {
    sourceId: DIVERGENCE_PROBE_SOURCE_ID,
    layer: "resolution",
    status: "success",
    subject,
    observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence: [
      {
        type: "resolution.divergence",
        subject,
        observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: {
          variants: summaries.map((summary) => ({ ...summary })),
          divergent: comparable ? divergentDimensions.length > 0 : null,
          divergentDimensions,
        },
      },
    ],
    findings: [],
  };
}

function divergentAmong(
  summaries: readonly DivergenceProbeVariantSummary[],
): DivergenceDimension[] {
  return DIVERGENCE_DIMENSIONS.filter((dimension) => {
    const values = new Set(summaries.map((summary) => summary[dimension]));
    return values.size > 1;
  });
}

function transportDegradation(
  outcome: Exclude<SafeFetchOutcome, { status: "success" }>,
  variant: string,
): EnrichmentOutcome {
  return degradationOutcome(
    outcome.subject.value,
    outcome.observedAt,
    outcome.status === "blocked" ? "skipped" : "failure",
    outcome.cause.code,
    retryableTransportCause(outcome.cause.code),
    { variant, ...(outcome.cause.details ?? {}) },
    [
      {
        type: "transport.attempt",
        subject: outcome.subject,
        observedAt: outcome.observedAt,
        provenance: declaredProvenance(),
        freshness: FRESHNESS,
        payload: transportPayload(outcome.evidence),
      },
    ],
  );
}

function degradationOutcome(
  url: string,
  observedAt: string,
  status: "skipped" | "failure",
  code: string,
  retryable: boolean,
  details?: EnrichmentPayload,
  suppliedEvidence: EnrichmentEvidence[] = [],
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: url };
  return {
    sourceId: DIVERGENCE_PROBE_SOURCE_ID,
    layer: "resolution",
    status,
    subject,
    observedAt,
    provenance: declaredProvenance(),
    freshness: FRESHNESS,
    evidence: [...suppliedEvidence],
    findings: [],
    cause: { code, retryable, ...(details === undefined ? {} : { details }) },
  };
}

function transportPayload(evidence: TransportEvidence): EnrichmentPayload {
  return {
    hop: evidence.hop,
    ...(evidence.protocol === undefined ? {} : { protocol: evidence.protocol }),
    ...(evidence.hostname === undefined ? {} : { hostname: evidence.hostname }),
    ...(evidence.port === undefined ? {} : { port: evidence.port }),
    ...(evidence.resolvedAddresses === undefined
      ? {}
      : { resolvedAddresses: [...evidence.resolvedAddresses] }),
    ...(evidence.selectedAddress === undefined
      ? {}
      : { selectedAddress: evidence.selectedAddress }),
  };
}

function declaredProvenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: {
      name: "@linklint/online.divergence-probe",
      version: DIVERGENCE_PROBE_SOURCE_VERSION,
    },
    data: null,
  };
}

function singleHeaderValue(
  headers: Readonly<Record<string, readonly string[]>>,
  name: string,
): string | null {
  const values = Object.entries(headers)
    .filter(([headerName]) => headerName.toLowerCase() === name)
    .flatMap(([, headerValues]) => [...headerValues]);
  if (values.length !== 1 || values[0]?.trim() === "") return null;
  return values[0]!.trim();
}

function canonicalHttpUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.href.length > MAX_PROBE_URL_LENGTH) return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function retryableTransportCause(code: string): boolean {
  return code === "dns-timeout" || code === "dns-error" || code === "connect-refused" ||
    code === "connect-timeout" || code === "connect-error" || code === "tls-handshake" ||
    code === "http-reset" || code === "http-timeout" || code === "http-error" ||
    code === "timeout";
}

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? Math.min(value, maximum)
    : fallback;
}

function observedInstant(now: () => Date): string {
  try {
    const date = now();
    return Number.isFinite(date.getTime()) ? date.toISOString() : new Date(0).toISOString();
  } catch {
    return new Date(0).toISOString();
  }
}

function report(outcomes: EnrichmentOutcome[]): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes };
}
