/**
 * Async enrichment contract (LINK-iprlxqxb K1 through LINK-isytbvjy K6).
 *
 * The FRAMEWORK for the roadmap resolution (L2) and reputation (L3) layers —
 * see docs/architecture.md §10. An {@link Enricher} is a caller-supplied,
 * opt-in async check that runs AFTER the synchronous lexical `inspect()` and
 * layers its findings onto the result. This module defines only the contract;
 * the runner lives in `inspect-async.ts` and no real network enricher ships in
 * this unit.
 *
 * Legacy findings deliberately MIRROR the lexical `DetectorFinding` shape
 * (`{ code, detail, confusables? }`) so they flow through the SAME
 * finding→reason→serialize path: the core attaches `layer`/`weight` from the
 * reason-code registry (`reasonMeta`/`weightFor`), exactly as it does for
 * lexical and policy findings. An enricher never supplies its own weight.
 *
 * K6 adds a versioned, source-attributed report around those findings. New
 * enrichers return {@link EnrichmentReport}; legacy `EnricherFinding[]` returns
 * remain accepted during the documented compatibility window and are wrapped as
 * provenance-incomplete outcomes by the runner.
 *
 * Per-finding `confidence` (K2, FR-SCORE-2b) IS here: an optional [0,1] measure
 * of how reliable a probabilistic signal is, min-aggregated into the result's
 * top-level `confidence`. Optional per-source cache metadata (K3, `cacheKey` /
 * `cacheTtlMs`) IS here too — the store itself lives in `enrichment-cache.ts`.
 * Per-source governance (K4): the bounded-timeout knob `timeoutMs` IS here; the
 * rate-limit / backoff state itself lives in `enrichment-governor.ts`.
 * Deliberately NOT here (clean seam left open): allowlist / feedback (K5).
 * {@link EnrichmentContext} is the single extension point those units grow — add
 * fields there without changing `enrich`'s arity.
 */

import { REASON_CODES, type ReasonCode } from "./reason-codes.js";
import type { Confusable } from "./result.js";
import type { Layer } from "./base.js";
import type { InspectResult } from "./result.js";

/**
 * The network-backed layers an enricher can belong to. A strict subset of
 * {@link Layer}: `lexical` is the synchronous built-in channel and `policy` is
 * the caller-configured advisory channel — neither is enrichable.
 */
export type EnrichmentLayer = Extract<Layer, "resolution" | "reputation">;

/** Version of the structured enrichment report nested in schema 1.3 results. */
export const ENRICHMENT_SCHEMA_VERSION = "1.0" as const;

/** JSON-safe values allowed in evidence payloads and cause details. */
export type EnrichmentJsonValue =
  | null
  | boolean
  | number
  | string
  | EnrichmentJsonValue[]
  | { readonly [key: string]: EnrichmentJsonValue };

/** Extensible, serialization-safe evidence payload. */
export interface EnrichmentPayload {
  readonly [key: string]: EnrichmentJsonValue;
}

/** The exact URL or host an outcome/evidence item describes. */
export interface EnrichmentSubject {
  kind: "url" | "host";
  value: string;
}

/** A named, optionally versioned source or dataset attribution. */
export interface EnrichmentProvenanceRef {
  /** Stable human/machine-readable name, e.g. `rdap.arin` or `caller.threat-feed`. */
  name: string;
  /** Source or dataset version when one exists. */
  version?: string;
  /** Public source identifier/URL when disclosure is safe and useful. */
  url?: string;
}

/**
 * Source and data attribution for an outcome.
 *
 * Structured enrichers MUST use `declared`. The other variants are emitted by
 * core only: `legacy-incomplete` makes the legacy migration visible without
 * inventing attribution, while `unavailable` is used when a source never
 * produced a valid report (abort, governor refusal, timeout, throw, or malformed
 * output).
 */
export type EnrichmentProvenance =
  | {
      kind: "declared";
      source: EnrichmentProvenanceRef;
      data: EnrichmentProvenanceRef | null;
    }
  | {
      kind: "legacy-incomplete" | "unavailable";
      source: null;
      data: null;
    };

/** Time-relative freshness of an outcome/evidence item. */
export interface EnrichmentFreshness {
  status: "fresh" | "stale" | "unknown";
  /** ISO-8601 expiry instant, or `null` when the source does not declare one. */
  expiresAt: string | null;
}

/** A structured artifact retained independently from the scored reason projection. */
export interface EnrichmentEvidence {
  /** Stable, source-defined evidence type, e.g. `http.redirect` or `rdap.domain`. */
  type: string;
  subject: EnrichmentSubject;
  /** ISO-8601 instant at which this artifact was observed. */
  observedAt: string;
  provenance: EnrichmentProvenance;
  freshness: EnrichmentFreshness;
  payload: EnrichmentPayload;
}

/** Machine-readable explanation for a skipped or failed source outcome. */
export interface EnrichmentCause {
  /** Stable source/framework-defined code. */
  code: string;
  /** Optional human explanation; callers should branch on `code`, not this text. */
  message?: string;
  retryable?: boolean;
  details?: EnrichmentPayload;
}

/**
 * An enricher's output. Structurally identical to a lexical `DetectorFinding`
 * (mirrored here rather than imported so `schema/` does not depend on
 * `detectors/`): the enricher supplies only the reason `code`, a human `detail`,
 * and — for confusable-style findings — the per-character expansion. The core
 * looks up `layer` and `weight` from the reason-code registry, so a finding is
 * scored and ordered exactly like a lexical one.
 */
export interface EnricherFinding {
  code: ReasonCode;
  detail: string;
  /** Per-character confusable entries that bubble up to top-level `confusables[]`. */
  confusables?: Confusable[];
  /**
   * How confident the enricher is in this probabilistic signal, in [0,1]
   * (FR-SCORE-2b). Omitting it means `1.0` (fully confident). The core folds
   * every successful finding's confidence into the result's top-level
   * `confidence` by taking the MINIMUM — a verdict is only as confident as its
   * least-confident contributing signal. Independent of scoring `weight`.
   */
  confidence?: number;
}

/** Fields common to every per-source structured outcome. */
interface EnrichmentOutcomeBase {
  /** Stable source identity; must exactly match the producing enricher's `id`. */
  sourceId: string;
  /** Must exactly match the producing enricher's registered layer. */
  layer: EnrichmentLayer;
  subject: EnrichmentSubject;
  /** ISO-8601 instant at which the source outcome was observed. */
  observedAt: string;
  provenance: EnrichmentProvenance;
  freshness: EnrichmentFreshness;
  /** Source artifacts. Empty is valid for no-hit/skipped/failure outcomes. */
  evidence: EnrichmentEvidence[];
  /** Scoring projection; only successful outcomes may contribute findings. */
  findings: EnricherFinding[];
}

/**
 * A per-source result. `no-hit` is a completed source query with no affirmative
 * match; `skipped` means policy/capacity/cancellation prevented completion;
 * `failure` means an attempted source operation did not complete cleanly. These
 * states are deliberately not collapsed into a benign result.
 */
export type EnrichmentOutcome =
  | (EnrichmentOutcomeBase & {
      status: "success" | "no-hit";
      cause?: never;
    })
  | (EnrichmentOutcomeBase & {
      status: "skipped" | "failure";
      cause: EnrichmentCause;
    });

/** Versioned structured output returned by new enrichers and exposed on results. */
export interface EnrichmentReport {
  schemaVersion: typeof ENRICHMENT_SCHEMA_VERSION;
  /** One source may emit several subject-specific outcomes (for example redirect hops). */
  outcomes: EnrichmentOutcome[];
}

/**
 * Enricher return during the compatibility window. New code returns a structured
 * report; the array form is the legacy scored-finding projection.
 */
export type EnricherOutput = EnrichmentReport | EnricherFinding[];

/** Expected source identity used when validating a report at the runner boundary. */
export interface EnrichmentIdentity {
  sourceId: string;
  layer: EnrichmentLayer;
}

/**
 * Runtime validator for the serialization-safe structured contract. When an
 * expected identity is supplied, every outcome must match it exactly. This is a
 * type guard only; callers that need diagnostics should report their own
 * source-specific validation details rather than exposing secrets through core.
 */
export function isEnrichmentReport(
  value: unknown,
  expected?: EnrichmentIdentity,
): value is EnrichmentReport {
  try {
    if (!isRecord(value)) return false;
    if (value.schemaVersion !== ENRICHMENT_SCHEMA_VERSION) return false;
    if (!Array.isArray(value.outcomes) || value.outcomes.length === 0) return false;
    return value.outcomes.every((outcome) => isEnrichmentOutcome(outcome, expected));
  } catch {
    return false;
  }
}

/** Runtime guard for the legacy findings-array compatibility shape. */
export function isEnricherFindingArray(value: unknown): value is EnricherFinding[] {
  try {
    return Array.isArray(value) && value.every(isFinding);
  } catch {
    return false;
  }
}

/**
 * Context handed to every enricher. The single forward-compatibility seam:
 * later units (cache, rate limiter, feedback) add fields here without changing
 * the `enrich` signature. For K1 it carries only the caller's `AbortSignal`,
 * threaded through from the async inspection options.
 *
 * An enricher SHOULD reject (throw) when `signal.aborted` becomes true; the
 * runner also treats an already-aborted signal as a skip before invoking the
 * enricher, so cancellation is always visible in `checksSkipped` and never
 * silently benign.
 */
export interface EnrichmentContext {
  /** Cancellation signal wired through from the caller's inspection options. */
  signal?: AbortSignal;
}

/**
 * A caller-supplied async check for a network-backed layer. Mirrors the lexical
 * {@link import("../detectors/types.js").Detector} contract (`id` + `layer` +
 * `run`), with an async `enrich` in place of the synchronous `run` and the
 * already-computed {@link InspectResult} (plus the {@link EnrichmentContext}) as
 * input instead of the parsed inspection context.
 *
 * Graceful degradation is load-bearing: an enricher that throws, rejects, or is
 * cancelled must NOT fail the whole async inspection — the runner records it in
 * `checksSkipped` (as `<layer>:<id>`) and continues. An enricher therefore need
 * not defend the boundary itself, but must be side-effect-free enough that a
 * mid-flight failure leaves nothing inconsistent.
 */
export interface Enricher {
  /** Stable identifier, unique within its layer. Forms the `<layer>:<id>` check token. */
  id: string;
  /** The network-backed layer this enricher contributes to. */
  layer: EnrichmentLayer;
  /**
   * Run the enrichment. Receives the synchronous inspection result (carrying the
   * original `input` and `parsed` components an enricher needs) and the
   * cancellation-carrying context. New implementations return a versioned
   * {@link EnrichmentReport}. The legacy findings array remains accepted during
   * the compatibility window and is exposed as provenance-incomplete.
   */
  enrich(result: InspectResult, ctx: EnrichmentContext): Promise<EnricherOutput>;
  /**
   * OPTIONAL result-cache key (LINK-wtnpkbkf, unit K3). When a cache is supplied
   * to `inspectAsync` AND this returns a non-null string, the pipeline reuses a
   * cached prior run under that key instead of calling {@link enrich} again; a
   * cache hit still counts as a run (recorded in `checksRun` as `<layer>:<id>`).
   *
   * Omitting `cacheKey`, or returning `null`, means this enricher is NEVER cached
   * (it runs every call). It is also never cached unless a positive, finite
   * {@link cacheTtlMs} is declared — a `cacheKey` without a TTL degrades to
   * "run fresh every time", never to a guessed default.
   *
   * PRIVACY (umbrella binding constraint, docs/architecture.md §10): the key is
   * ENTIRELY the enricher's responsibility and the framework NEVER derives one
   * from the full URL. An enricher MUST key on a privacy-preserving projection —
   * e.g. the registrable domain or a hash-prefix — and MUST NOT return the full
   * URL (or anything from which it can be reconstructed) as the key.
   */
  cacheKey?(result: InspectResult): string | null;
  /**
   * OPTIONAL per-source time-to-live, in milliseconds, for entries this enricher
   * writes (LINK-wtnpkbkf, unit K3). Applied per `set()`, so each enricher's cache
   * entries expire on their own schedule ("per-source TTLs"). Required (positive,
   * finite) for caching to take effect: if {@link cacheKey} yields a key but this
   * is absent/non-positive, the enricher runs fresh every call and nothing is
   * stored.
   */
  cacheTtlMs?: number;
  /**
   * OPTIONAL per-source bounded timeout, in milliseconds (LINK-bergliii, unit K4).
   * Takes effect ONLY when a governor is supplied to `inspectAsync`; it OVERRIDES
   * the governor's default timeout for this source. When present (positive,
   * finite) the pipeline races {@link enrich} against it: on timeout the enricher
   * is aborted (its context `signal` fires) and degrades to `checksSkipped`
   * (`<layer>:<id>`), recording a failure for backoff. A slow enricher can NEVER
   * stall the verdict past this bound — the race is enforced by the runner, so it
   * holds even if the enricher ignores its signal. Absent/non-positive falls back
   * to the governor default; with no governor, no timeout applies (K1–K3 path).
   */
  timeoutMs?: number;
}

function isEnrichmentOutcome(
  value: unknown,
  expected: EnrichmentIdentity | undefined,
): value is EnrichmentOutcome {
  if (!isRecord(value)) return false;
  if (!isNonEmptyString(value.sourceId) || !isEnrichmentLayer(value.layer)) return false;
  if (
    expected !== undefined &&
    (value.sourceId !== expected.sourceId || value.layer !== expected.layer)
  ) {
    return false;
  }
  if (!isSubject(value.subject) || !isIsoInstant(value.observedAt)) return false;
  if (!isProvenance(value.provenance) || !isFreshness(value.freshness)) return false;
  if (!Array.isArray(value.evidence) || !value.evidence.every(isEvidence)) return false;
  if (!Array.isArray(value.findings) || !value.findings.every(isFinding)) return false;

  if (value.status === "success") {
    // An empty successful source is semantically a no-hit, so reject ambiguity.
    return value.findings.length > 0 || value.evidence.length > 0;
  }
  if (value.status === "no-hit") return value.findings.length === 0;
  if (value.status === "skipped" || value.status === "failure") {
    return value.findings.length === 0 && isCause(value.cause);
  }
  return false;
}

function isEvidence(value: unknown): value is EnrichmentEvidence {
  return (
    isRecord(value) &&
    isNonEmptyString(value.type) &&
    isSubject(value.subject) &&
    isIsoInstant(value.observedAt) &&
    isProvenance(value.provenance) &&
    isFreshness(value.freshness) &&
    isPayload(value.payload)
  );
}

function isFinding(value: unknown): value is EnricherFinding {
  if (
    !isRecord(value) ||
    !isNonEmptyString(value.code) ||
    !Object.hasOwn(REASON_CODES, value.code)
  ) {
    return false;
  }
  if (typeof value.detail !== "string") return false;
  if (
    value.confidence !== undefined &&
    (typeof value.confidence !== "number" ||
      !Number.isFinite(value.confidence) ||
      value.confidence < 0 ||
      value.confidence > 1)
  ) {
    return false;
  }
  return value.confusables === undefined ||
    (Array.isArray(value.confusables) && value.confusables.every(isConfusable));
}

function isConfusable(value: unknown): value is Confusable {
  return (
    isRecord(value) &&
    typeof value.char === "string" &&
    isNonEmptyString(value.codepoint) &&
    isNonEmptyString(value.confusableWith) &&
    (value.component === "host" || value.component === "path" || value.component === "query") &&
    typeof value.position === "number" &&
    Number.isInteger(value.position) &&
    value.position >= 0
  );
}

function isSubject(value: unknown): value is EnrichmentSubject {
  return (
    isRecord(value) &&
    (value.kind === "url" || value.kind === "host") &&
    typeof value.value === "string"
  );
}

function isProvenance(value: unknown): value is EnrichmentProvenance {
  if (!isRecord(value)) return false;
  if (value.kind === "declared") {
    return isProvenanceRef(value.source) &&
      (value.data === null || isProvenanceRef(value.data));
  }
  if (value.kind === "legacy-incomplete" || value.kind === "unavailable") {
    return value.source === null && value.data === null;
  }
  return false;
}

function isProvenanceRef(value: unknown): value is EnrichmentProvenanceRef {
  return (
    isRecord(value) &&
    isNonEmptyString(value.name) &&
    (value.version === undefined || isNonEmptyString(value.version)) &&
    (value.url === undefined || isNonEmptyString(value.url))
  );
}

function isFreshness(value: unknown): value is EnrichmentFreshness {
  return (
    isRecord(value) &&
    (value.status === "fresh" || value.status === "stale" || value.status === "unknown") &&
    (value.expiresAt === null || isIsoInstant(value.expiresAt))
  );
}

function isCause(value: unknown): value is EnrichmentCause {
  return (
    isRecord(value) &&
    isNonEmptyString(value.code) &&
    (value.message === undefined || typeof value.message === "string") &&
    (value.retryable === undefined || typeof value.retryable === "boolean") &&
    (value.details === undefined || isPayload(value.details))
  );
}

function isPayload(value: unknown): value is EnrichmentPayload {
  return isRecord(value) && isJsonValue(value, new Set());
}

function isJsonValue(value: unknown, seen: Set<object>): value is EnrichmentJsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  const valid = Array.isArray(value)
    ? value.every((item) => isJsonValue(item, seen))
    : isRecord(value) && Object.values(value).every((item) => isJsonValue(item, seen));
  seen.delete(value);
  return valid;
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function isEnrichmentLayer(value: unknown): value is EnrichmentLayer {
  return value === "resolution" || value === "reputation";
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
