import type {
  Confusable,
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentLayer,
  InspectOptions,
  InspectResult,
  Reason,
} from "./schema/types.js";
import { inspect } from "./inspect.js";
import { reasonMeta, weightFor } from "./schema/reason-codes.js";
import { aggregate } from "./scoring/score.js";

/**
 * Options for {@link inspectAsync}. A superset of the synchronous
 * {@link InspectOptions}: everything `inspect()` understands (tuning knobs,
 * policy axes, agent mode) plus the opt-in async surface.
 */
export interface InspectAsyncOptions extends InspectOptions {
  /**
   * Caller-supplied async enrichers to run after the synchronous lexical pass.
   * Enrichment is opt-in: with none supplied (or an empty array) the result is
   * byte-for-byte identical to `inspect(input, options)`.
   */
  enrichers?: Enricher[];
  /**
   * Cancellation signal, threaded into every enricher's {@link EnrichmentContext}.
   * An already-aborted signal, or an enricher that rejects on abort, degrades to
   * a `checksSkipped` marker for that enricher.
   */
  signal?: AbortSignal;
}

/** The bare per-layer placeholder tokens `inspect()` seeds into `checksSkipped`. */
const LAYER_PLACEHOLDERS: readonly EnrichmentLayer[] = ["resolution", "reputation"];

/** Per-enricher outcome after running (or declining to run) it. */
type EnricherOutcome =
  | { kind: "run"; token: string; findings: EnricherFinding[] }
  | { kind: "skipped"; token: string };

/**
 * Async, opt-in enrichment entry point (LINK-iprlxqxb, unit K1).
 *
 * FIRST runs the synchronous, zero-network `inspect()` unchanged, THEN layers
 * caller-supplied {@link Enricher}s (the roadmap resolution/reputation layers —
 * docs/architecture.md §10) on top. This function performs NO network I/O
 * itself; all network behaviour lives in the caller's enrichers.
 *
 * Contract:
 *  - **No enrichers → byte-identical.** With an empty/absent `enrichers` list
 *    the returned result is exactly `inspect(input, options)`.
 *  - **Successful enricher → visible in `checksRun`** as `<layer>:<id>`, and its
 *    findings merge into `reasons`/`confusables`/`score` through the SAME
 *    reason-code registry path (`reasonMeta`/`weightFor`/`aggregate`) as lexical
 *    findings.
 *  - **Never silently clean.** An enricher that throws, rejects, or is cancelled
 *    degrades to a `<layer>:<id>` entry in `checksSkipped` — one enricher failing
 *    never fails the whole call. A layer with NO enricher supplied keeps its bare
 *    `resolution`/`reputation` placeholder in `checksSkipped`.
 *
 * Graceful degradation is load-bearing (FR-D-13 parallel): the runner guards
 * every enricher; a rejection is recorded, not propagated.
 */
export async function inspectAsync(
  input: string,
  options: InspectAsyncOptions = {},
): Promise<InspectResult> {
  // Stage 1: the synchronous lexical result, produced exactly as today. Passing
  // the superset options is safe — inspect() reads only the keys it knows.
  const base = inspect(input, options);

  const enrichers = options.enrichers ?? [];
  if (enrichers.length === 0) return base;

  // Stage 2: run every enricher under a guard so one failure can't abort the
  // call. Order is the caller's supply order, keeping the output deterministic.
  const ctx: EnrichmentContext =
    options.signal !== undefined ? { signal: options.signal } : {};
  const outcomes = await Promise.all(
    enrichers.map((enricher) => runEnricher(enricher, base, ctx)),
  );

  // Stage 3: fold the outcomes back onto the base result.
  const configuredLayers = new Set<EnrichmentLayer>(enrichers.map((e) => e.layer));

  const enrichmentFindings: EnricherFinding[] = [];
  const runTokens: string[] = [];
  const skippedTokens: string[] = [];
  for (const outcome of outcomes) {
    if (outcome.kind === "run") {
      runTokens.push(outcome.token);
      enrichmentFindings.push(...outcome.findings);
    } else {
      skippedTokens.push(outcome.token);
    }
  }

  // Merge findings into reasons via the SAME registry-driven path serialize.ts
  // uses: layer + weight come from the reason code, never from the enricher.
  const enrichmentReasons: Reason[] = enrichmentFindings.map((f) => ({
    code: f.code,
    layer: reasonMeta(f.code).layer,
    detail: f.detail,
    weight: weightFor(f.code),
  }));
  const reasons: Reason[] = [...base.reasons, ...enrichmentReasons];
  reasons.sort((a, b) => b.weight - a.weight || a.code.localeCompare(b.code));

  const confusables: Confusable[] = [
    ...base.confusables,
    ...enrichmentFindings.flatMap((f) => f.confusables ?? []),
  ];

  // Re-aggregate scoring only for parseable input. Invalid input stays
  // fail-closed with `score: null` (docs/architecture.md §6) even under
  // enrichment.
  let score = base.score;
  let severity = base.severity;
  if (base.status === "ok") {
    ({ score, severity } = aggregate(reasons));
  }

  // Confidence (FR-SCORE-2b) is INDEPENDENT of score/weight: it does not feed
  // the probabilistic-OR aggregation above. The verdict is only as confident as
  // its least-confident contributing signal, so we take the MINIMUM over the
  // deterministic lexical base (1.0) and every SUCCESSFUL enricher finding's
  // confidence (default 1.0 when omitted). A skipped/failed enricher contributes
  // nothing — its absence is already visible in checksSkipped. With no findings
  // this stays base.confidence (1.0), preserving the no-enricher invariant.
  const confidence = Math.min(
    base.confidence,
    ...enrichmentFindings.map((f) => f.confidence ?? 1),
  );

  // A configured layer is no longer wholesale-skipped: drop its bare placeholder
  // (per-enricher outcomes now speak for it). An unconfigured layer keeps its
  // placeholder, so an unchecked layer is never silently clean.
  const checksSkipped = [
    ...base.checksSkipped.filter(
      (token) =>
        !(
          LAYER_PLACEHOLDERS.includes(token as EnrichmentLayer) &&
          configuredLayers.has(token as EnrichmentLayer)
        ),
    ),
    ...skippedTokens,
  ];
  const checksRun = [...base.checksRun, ...runTokens];

  return {
    ...base,
    reasons,
    confusables,
    score,
    severity,
    confidence,
    checksRun,
    checksSkipped,
  };
}

/**
 * Run a single enricher behind a total guard. Resolves to a `run` outcome with
 * its findings on success, or a `skipped` outcome on cancellation, rejection, or
 * a malformed (non-array) return. Never rejects — graceful degradation is the
 * whole point.
 */
async function runEnricher(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
): Promise<EnricherOutcome> {
  const token = `${enricher.layer}:${enricher.id}`;
  // A signal already aborted before we start: skip without invoking.
  if (ctx.signal?.aborted) return { kind: "skipped", token };
  try {
    const findings = await enricher.enrich(base, ctx);
    // A completion observed after cancellation is treated as skipped, so an
    // enricher that ignores the signal still degrades rather than leaking.
    if (ctx.signal?.aborted) return { kind: "skipped", token };
    if (!Array.isArray(findings)) return { kind: "skipped", token };
    return { kind: "run", token, findings };
  } catch {
    // Any throw/rejection (including an abort) degrades to a skip.
    return { kind: "skipped", token };
  }
}
