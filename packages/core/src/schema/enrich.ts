/**
 * Async enrichment contract (LINK-iprlxqxb, unit K1).
 *
 * The FRAMEWORK for the roadmap resolution (L2) and reputation (L3) layers —
 * see docs/architecture.md §10. An {@link Enricher} is a caller-supplied,
 * opt-in async check that runs AFTER the synchronous lexical `inspect()` and
 * layers its findings onto the result. This module defines only the contract;
 * the runner lives in `inspect-async.ts` and no real network enricher ships in
 * this unit.
 *
 * Findings deliberately MIRROR the lexical `DetectorFinding` shape
 * (`{ code, detail, confusables? }`) so they flow through the SAME
 * finding→reason→serialize path: the core attaches `layer`/`weight` from the
 * reason-code registry (`reasonMeta`/`weightFor`), exactly as it does for
 * lexical and policy findings. An enricher never supplies its own weight.
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

import type { ReasonCode } from "./reason-codes.js";
import type { Confusable } from "./result.js";
import type { Layer } from "./base.js";
import type { InspectResult } from "./result.js";

/**
 * The network-backed layers an enricher can belong to. A strict subset of
 * {@link Layer}: `lexical` is the synchronous built-in channel and `policy` is
 * the caller-configured advisory channel — neither is enrichable.
 */
export type EnrichmentLayer = Extract<Layer, "resolution" | "reputation">;

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
   * cancellation-carrying context. Resolves to zero or more findings.
   */
  enrich(result: InspectResult, ctx: EnrichmentContext): Promise<EnricherFinding[]>;
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
