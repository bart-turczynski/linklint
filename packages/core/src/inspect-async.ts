import type {
  Confusable,
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentLayer,
  EnrichmentOutcome,
  EnrichmentReport,
  EnrichmentSubject,
  EnricherOutput,
  InspectOptions,
  InspectResult,
  Reason,
} from "./schema/types.js";
import type { EnrichmentCache } from "./enrichment-cache.js";
import type { EnrichmentGovernor } from "./enrichment-governor.js";
import { inspect } from "./inspect.js";
import { reasonMeta, weightFor } from "./schema/reason-codes.js";
import { aggregate } from "./scoring/score.js";
import { applySuppressions, suppressionHostContext } from "./scoring/suppress.js";
import { normalizeSuppressReasons } from "./parse/runtime.js";
import {
  ENRICHMENT_SCHEMA_VERSION,
  isEnricherFindingArray,
  isEnrichmentReport,
} from "./schema/enrich.js";

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
  /**
   * Opt-in result cache (LINK-wtnpkbkf, unit K3). When supplied, an enricher that
   * declares a `cacheKey` (+ positive `cacheTtlMs`) is served from the cache on a
   * hit — its `enrich` is NOT called, yet it still counts as run (`<layer>:<id>`
   * in `checksRun`). Absent this option, or for an enricher without a `cacheKey`,
   * the pipeline behaves exactly as K1/K2. Caching is never on by default.
   */
  cache?: EnrichmentCache;
  /**
   * Opt-in per-source governor (LINK-bergliii, unit K4): a bounded timeout,
   * token-bucket rate limit, and exponential backoff, all keyed by the enricher's
   * `<layer>:<id>` token. When supplied, a source that is over its timeout, out of
   * tokens, or in an open backoff window degrades to `checksSkipped` — one slow or
   * failing source can never block the verdict. Consulted only on a cache MISS
   * (see {@link InspectAsyncOptions.cache}): a cache HIT never consumes a token,
   * starts a timeout, or touches backoff, because no network happened. Absent this
   * option the pipeline behaves exactly as K1–K3 — governance is never on by
   * default. See {@link import("./enrichment-governor.js").EnrichmentGovernor}.
   */
  governor?: EnrichmentGovernor;
}

/** The bare per-layer placeholder tokens `inspect()` seeds into `checksSkipped`. */
const LAYER_PLACEHOLDERS: readonly EnrichmentLayer[] = ["resolution", "reputation"];

/** Validated per-enricher report after running (or declining to run) it. */
interface EnricherRun {
  token: string;
  report: EnrichmentReport;
}

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
  const cache = options.cache;
  const governor = options.governor;
  const runs = await Promise.all(
    enrichers.map((enricher) => runEnricher(enricher, base, ctx, cache, governor)),
  );

  // Stage 3: fold the outcomes back onto the base result.
  const configuredLayers = new Set<EnrichmentLayer>(enrichers.map((e) => e.layer));

  const enrichmentFindings: EnricherFinding[] = [];
  const enrichmentOutcomes: EnrichmentOutcome[] = [];
  const runTokens: string[] = [];
  const skippedTokens: string[] = [];
  for (const run of runs) {
    enrichmentOutcomes.push(...run.report.outcomes);
    const completed = run.report.outcomes.some(
      (outcome) => outcome.status === "success" || outcome.status === "no-hit",
    );
    const incomplete = run.report.outcomes.some(
      (outcome) => outcome.status === "skipped" || outcome.status === "failure",
    );
    if (completed) runTokens.push(run.token);
    if (incomplete) skippedTokens.push(run.token);
    for (const outcome of run.report.outcomes) {
      if (outcome.status === "success") enrichmentFindings.push(...outcome.findings);
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
  // Enricher reasons are heuristics too, so the caller false-positive escape
  // hatch must reach them: re-run suppression over the MERGED set (the sync base
  // reasons were already suppressed by inspect() with these same rules, so
  // re-applying is idempotent — only fresh enricher reasons can newly match).
  // Inert when no rule is configured, preserving the no-enricher/no-option
  // invariant. The `suppression` marker already rides on base.checksRun.
  const suppressReasons = normalizeSuppressReasons(options.suppressReasons);
  const reasons: Reason[] = applySuppressions(
    [...base.reasons, ...enrichmentReasons],
    suppressReasons,
    suppressionHostContext(base.parsed?.registrableDomain ?? null),
  );
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
    enrichment: {
      schemaVersion: ENRICHMENT_SCHEMA_VERSION,
      outcomes: enrichmentOutcomes,
    },
  };
}

/** Race sentinel: the bounded timeout fired (or the caller's signal aborted). */
const TIMED_OUT = Symbol("timed-out");

/**
 * Run a single enricher behind a total guard. Resolves to a validated structured
 * report on success/no-hit or to an explicit skipped/failure report on
 * cancellation, rejection, invalid output, governor refusal, or timeout. Never
 * rejects — graceful degradation is the whole point.
 *
 * Ordering (K3 cache × K4 governor — the interplay matters):
 *  1. **Already-aborted signal → skip** without touching cache or governor.
 *  2. **Cache FIRST.** A HIT (LINK-wtnpkbkf, K3) returns the cached output
 *     WITHOUT calling `enrich`, and MUST NOT consume a rate-limit
 *     token, start a timeout, or touch backoff — no network happened.
 *  3. On a cache MISS, **consult the governor** (LINK-bergliii, K4) if supplied:
 *     rate-limited OR in an open backoff window → skip (never call `enrich`).
 *     Admission consumes exactly one token.
 *  4. Otherwise run `enrich` under the bounded timeout. Timeout, throw/reject,
 *     observed post-abort, or a malformed return → skip AND record a governor
 *     failure (backoff); the result is NEVER cached. A clean success → record a
 *     governor success (reset backoff), and store complete success/no-hit output.
 *
 * With no governor the timeout/rate-limit/backoff machinery is entirely inert, so
 * this path stays byte-for-byte K1–K3.
 */
async function runEnricher(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
  cache: EnrichmentCache | undefined,
  governor: EnrichmentGovernor | undefined,
): Promise<EnricherRun> {
  const token = `${enricher.layer}:${enricher.id}`;
  // A signal already aborted before we start: skip without invoking. Checked
  // BEFORE the cache so an aborted call never even reads from it.
  if (ctx.signal?.aborted) {
    return {
      token,
      report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
    };
  }

  // Resolve the (optional) cache slot. The key is entirely enricher-supplied —
  // the framework never derives it from the URL (privacy constraint).
  const slot = cache !== undefined ? cacheSlotFor(enricher, base, cache) : null;
  if (slot !== null) {
    const cached = slot.cache.get(slot.key);
    // Cache HIT: a successful prior run stands in for this one. It still counts
    // as run, so its report/findings flow through exactly like fresh output.
    // No token is spent and no timeout starts — cache-before-governor is the point.
    if (cached !== undefined) {
      return {
        token,
        report:
          normalizeOutput(cached, enricher, base) ??
          frameworkReport(enricher, base, "failure", "invalid-cached-output", false),
      };
    }
  }

  // Cache MISS: consult the governor (if any) before spending a network call.
  let timeoutMs = enricher.timeoutMs;
  if (governor !== undefined) {
    const decision = governor.admit(token);
    if (!decision.run) {
      return {
        token,
        report: frameworkReport(enricher, base, "skipped", "governor-denied", true),
      };
    }
    // Enricher's own timeout wins; otherwise fall back to the governor default.
    timeoutMs = enricher.timeoutMs ?? decision.timeoutMs;
  } else {
    // No governor → no timeout/rate-limit/backoff at all (K1–K3 path exactly).
    timeoutMs = undefined;
  }

  try {
    const outcome = await runWithTimeout(enricher, base, ctx, timeoutMs);
    if (outcome === TIMED_OUT) {
      // The bounded timeout fired (or the signal aborted mid-race): degrade and
      // record a failure so repeated slowness opens a backoff window.
      governor?.recordFailure(token);
      if (ctx.signal?.aborted) {
        return {
          token,
          report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
        };
      }
      return {
        token,
        report: frameworkReport(enricher, base, "failure", "timeout", true),
      };
    }
    // A completion observed after cancellation is treated as skipped, so an
    // enricher that ignores the signal still degrades rather than leaking. A
    // cancelled run is NEVER cached; it counts as a failure for backoff.
    if (ctx.signal?.aborted) {
      governor?.recordFailure(token);
      return {
        token,
        report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
      };
    }
    const report = normalizeOutput(outcome, enricher, base);
    if (report === null) {
      governor?.recordFailure(token);
      return {
        token,
        report: frameworkReport(enricher, base, "failure", "invalid-output", false),
      };
    }
    // A source-declared failure feeds backoff; successful/no-hit/skipped reports
    // are clean protocol completions. Only wholly completed success/no-hit reports
    // are cached — partial, skipped, and failed reports are never negative-cached.
    if (report.outcomes.some((item) => item.status === "failure")) {
      governor?.recordFailure(token);
    } else {
      governor?.recordSuccess(token);
    }
    if (
      slot !== null &&
      report.outcomes.every((item) => item.status === "success" || item.status === "no-hit")
    ) {
      slot.cache.set(slot.key, outcome, slot.ttlMs);
    }
    return { token, report };
  } catch {
    // Any throw/rejection is never cached and is counted for backoff. A caller
    // abort stays a skip; other source errors become explicit failures.
    governor?.recordFailure(token);
    if (ctx.signal?.aborted) {
      return {
        token,
        report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
      };
    }
    return {
      token,
      report: frameworkReport(enricher, base, "failure", "source-error", true),
    };
  }
}

/**
 * Run `enrich` bounded by `timeoutMs`. Returns the enricher's output, or the
 * {@link TIMED_OUT} sentinel when the timeout (or the caller's signal) fires first.
 *
 * When a positive, finite timeout is set, a timer-driven {@link AbortController}
 * is composed with the caller's signal via `AbortSignal.any` (Node 24), and the
 * composed signal is threaded into the enricher's context so a well-behaved
 * enricher aborts on time. The runner ALSO races `enrich` against that signal, so
 * even an enricher that ignores its signal cannot stall the verdict past the
 * bound — the race is the hard guarantee. A timer-driven controller (rather than
 * `AbortSignal.timeout`) is used so tests can drive the timeout with fake timers,
 * never real wall-clock sleeps.
 *
 * With no (or a non-positive) timeout this is exactly the K1 call: `enrich(base,
 * ctx)` with the caller's own context, unbounded.
 */
async function runWithTimeout(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
  timeoutMs: number | undefined,
): Promise<EnricherOutput | typeof TIMED_OUT> {
  if (timeoutMs === undefined || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return enricher.enrich(base, ctx);
  }

  const timeoutController = new AbortController();
  const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
  const signals = ctx.signal
    ? [ctx.signal, timeoutController.signal]
    : [timeoutController.signal];
  const composed = AbortSignal.any(signals);
  const enrichCtx: EnrichmentContext = { ...ctx, signal: composed };

  const timeoutRace = new Promise<typeof TIMED_OUT>((resolve) => {
    if (composed.aborted) {
      resolve(TIMED_OUT);
      return;
    }
    composed.addEventListener("abort", () => resolve(TIMED_OUT), { once: true });
  });

  try {
    // Promise.race keeps a reaction attached to the enrich promise even after the
    // timeout wins, so a late rejection of the abandoned call is never unhandled.
    return await Promise.race([enricher.enrich(base, enrichCtx), timeoutRace]);
  } finally {
    clearTimeout(timer);
  }
}

/** Validate structured output or adapt a legacy findings array without inventing provenance. */
function normalizeOutput(
  output: unknown,
  enricher: Enricher,
  base: InspectResult,
): EnrichmentReport | null {
  if (isEnricherFindingArray(output)) return legacyReport(enricher, base, output);
  if (
    !isEnrichmentReport(output, { sourceId: enricher.id, layer: enricher.layer }) ||
    output.outcomes.some(
      (item) =>
        item.provenance.kind !== "declared" ||
        item.evidence.some((evidence) => evidence.provenance.kind !== "declared"),
    )
  ) {
    return null;
  }
  return output;
}

/** Compatibility adapter for the pre-K6 flat output. Empty arrays remain visibly ambiguous. */
function legacyReport(
  enricher: Enricher,
  base: InspectResult,
  findings: EnricherFinding[],
): EnrichmentReport {
  const observedAt = new Date().toISOString();
  const subject = inspectionSubject(base);
  const provenance = { kind: "legacy-incomplete", source: null, data: null } as const;
  const freshness = { status: "unknown", expiresAt: null } as const;
  return {
    schemaVersion: ENRICHMENT_SCHEMA_VERSION,
    outcomes: [
      {
        sourceId: enricher.id,
        layer: enricher.layer,
        status: "success",
        subject,
        observedAt,
        provenance,
        freshness,
        evidence:
          findings.length === 0
            ? [
                {
                  type: "legacy.empty-result",
                  subject,
                  observedAt,
                  provenance,
                  freshness,
                  payload: { semantics: "unknown" },
                },
              ]
            : [],
        findings,
      },
    ],
  };
}

/** Build an explicit framework-owned degradation outcome. */
function frameworkReport(
  enricher: Enricher,
  base: InspectResult,
  status: "skipped" | "failure",
  code: string,
  retryable: boolean,
): EnrichmentReport {
  return {
    schemaVersion: ENRICHMENT_SCHEMA_VERSION,
    outcomes: [
      {
        sourceId: enricher.id,
        layer: enricher.layer,
        status,
        subject: inspectionSubject(base),
        observedAt: new Date().toISOString(),
        provenance: { kind: "unavailable", source: null, data: null },
        freshness: { status: "unknown", expiresAt: null },
        evidence: [],
        findings: [],
        cause: { code, retryable },
      },
    ],
  };
}

/** The subject core can state truthfully without guessing what a source queried. */
function inspectionSubject(base: InspectResult): EnrichmentSubject {
  if (base.parsed?.scheme === null && base.parsed.effectiveHost !== null) {
    return { kind: "host", value: base.parsed.effectiveHost };
  }
  return { kind: "url", value: base.input };
}

/** A resolved cache slot: the store, the namespaced key, and the TTL to write. */
interface CacheSlot {
  cache: EnrichmentCache;
  key: string;
  ttlMs: number;
}

/**
 * Resolve an enricher's cache slot for this inspection, or `null` if it is not
 * cacheable. An enricher is cacheable only when it declares BOTH a `cacheKey`
 * that returns a non-null string AND a positive, finite `cacheTtlMs` — a missing
 * TTL degrades to "run fresh every call", never to a guessed default.
 *
 * The returned key is namespaced by the enricher's `<layer>:<id>` check token so
 * two enrichers can never collide on the same caller-supplied key, keeping their
 * entries (and TTLs) independent. `cacheKey` is caller code, so a throw from it
 * degrades to "not cacheable" rather than failing the call.
 */
function cacheSlotFor(
  enricher: Enricher,
  base: InspectResult,
  cache: EnrichmentCache,
): CacheSlot | null {
  if (typeof enricher.cacheKey !== "function") return null;
  const ttlMs = enricher.cacheTtlMs;
  if (typeof ttlMs !== "number" || !Number.isFinite(ttlMs) || ttlMs <= 0) return null;
  let key: string | null;
  try {
    key = enricher.cacheKey(base);
  } catch {
    return null;
  }
  if (key === null || key === undefined) return null;
  // NUL separator cannot appear in a well-formed check token, so no <layer>:<id>
  // prefix can bleed into an adjacent enricher's caller-supplied key.
  return { cache, key: `${enricher.layer}:${enricher.id} ${key}`, ttlMs };
}
