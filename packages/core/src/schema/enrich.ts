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
 * Deliberately NOT here (later units, clean seams left open): per-finding
 * confidence (K2), caching (K3), rate-limit / timeout / backoff policy (K4),
 * allowlist / feedback (K5). {@link EnrichmentContext} is the single extension
 * point those units grow — add fields there without changing `enrich`'s arity.
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
}
