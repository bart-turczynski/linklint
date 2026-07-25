import type {
  Confusable,
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentFrameworkCauseCode,
  EnrichmentLayer,
  EnrichmentOutcome,
  EnrichmentPayload,
  EnrichmentPlan,
  EnrichmentReport,
  EnrichmentSubject,
  EnricherOutput,
  InspectOptions,
  InspectResult,
  Reason,
} from "./schema/types.js";
import type { EnrichmentCache } from "./enrichment-cache.js";
import type { EnrichmentGovernor, GovernorDecision } from "./enrichment-governor.js";
import { inspect } from "./inspect.js";
import { compareReasons, reasonMeta, weightFor } from "./schema/reason-codes.js";
import { aggregate } from "./scoring/score.js";
import { applySuppressions, suppressionSubjectHostContext } from "./scoring/suppress.js";
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
   * Caller-ordered enrichment plan to run after the synchronous lexical pass.
   * An enricher may declare `dependsOn` check tokens; the runner derives stable
   * sequential stages while executing independent steps within a stage in
   * parallel. With no dependencies this is the original flat parallel runner.
   * Enrichment is opt-in: with none supplied (or an empty array) the result is
   * byte-for-byte identical to `inspect(input, options)`.
   */
  enrichers?: EnrichmentPlan;
  /**
   * Cancellation signal, threaded into every enricher's {@link EnrichmentContext}.
   * An already-aborted signal, or an enricher that rejects on abort, degrades to
   * a `checksSkipped` marker for that enricher.
   */
  signal?: AbortSignal;
  /**
   * Opt-in result cache (LINK-wtnpkbkf K3, LINK-xwgzgyfu K9). Synchronous and
   * Promise-capable stores are supported. An enricher that declares a `cacheKey`
   * plus either static `cacheTtlMs` or dynamic `cacheTtlMsFor` policy is served
   * from the cache on a hit — its `enrich` is NOT called, yet it still counts as
   * run (`<layer>:<id>` in `checksRun`). Absent this option, or for an enricher
   * without a cache key/TTL policy, caching is never enabled implicitly.
   */
  cache?: EnrichmentCache;
  /**
   * Opt-in per-source governor (LINK-bergliii, K4): token-bucket rate limiting,
   * exponential backoff, and an optional timeout policy, all keyed by the
   * enricher's `<layer>:<id>` token. The K8 runner deadline is always active by
   * default and does not require this option. A cache HIT never consults the
   * governor because no network happened. See
   * {@link import("./enrichment-governor.js").EnrichmentGovernor}.
   */
  governor?: EnrichmentGovernor;
}

/** The bare per-layer placeholder tokens `inspect()` seeds into `checksSkipped`. */
const LAYER_PLACEHOLDERS: readonly EnrichmentLayer[] = ["resolution", "reputation"];

/** Safe hard deadline applied to every configured enricher unless explicitly disabled. */
export const DEFAULT_ENRICHMENT_TIMEOUT_MS = 5000;

/** Validated per-enricher report after running (or declining to run) it. */
interface EnricherRun {
  token: string;
  report: EnrichmentReport;
}

/** One caller-ordered node in the dependency execution plan. */
interface PlannedEnricher {
  index: number;
  token: string;
  enricher: Enricher;
  dependencies: readonly string[];
  dependencyShapeValid: boolean;
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
 *  - **Dependencies are explicit.** Independent plan nodes run concurrently;
 *    dependent nodes see prior structured outcomes and run only after every
 *    prerequisite wholly completes. Unavailable prerequisites and invalid/cyclic
 *    plans become attributed skipped outcomes rather than implicit work.
 *  - **Bounded and total.** Every configured source receives a hard 5s runner
 *    deadline unless a positive finite override or explicit `null` opt-out is
 *    declared. Enricher, cache-key, cache, and governor exceptions become
 *    structured degradation outcomes; they never escape this function.
 *
 * Graceful degradation is load-bearing (FR-D-13 parallel): the runner guards
 * every pluggable boundary; a rejection is recorded, not propagated.
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

  // Stage 2: derive deterministic topological stages from optional dependency
  // tokens. Independent steps run concurrently; downstream steps receive a
  // stable snapshot of all outcomes accumulated by prior stages.
  const cache = options.cache;
  const governor = options.governor;
  const runs = await executeEnrichmentPlan(
    enrichers,
    base,
    options.signal,
    cache,
    governor,
  );

  // Stage 3: fold the outcomes back onto the base result.
  const configuredLayers = new Set<EnrichmentLayer>(enrichers.map((e) => e.layer));

  const enrichmentFindings: Array<{
    finding: EnricherFinding;
    subject: EnrichmentSubject;
  }> = [];
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
      if (outcome.status === "success") {
        enrichmentFindings.push(
          ...outcome.findings.map((finding) => ({ finding, subject: outcome.subject })),
        );
      }
    }
  }

  // Merge findings into reasons via the SAME registry-driven path serialize.ts
  // uses: layer + weight come from the reason code, never from the enricher.
  const suppressReasons = normalizeSuppressReasons(options.suppressReasons);
  const enrichmentReasons: Reason[] = enrichmentFindings.map(({ finding, subject }) => {
    const projected: Reason = {
      code: finding.code,
      layer: reasonMeta(finding.code).layer,
      detail: finding.detail,
      weight: weightFor(finding.code),
    };
    return applySuppressions(
      [projected],
      suppressReasons,
      suppressionSubjectHostContext(subject),
    )[0]!;
  });
  // Enricher reasons are heuristics too, so the caller false-positive escape
  // hatch must reach them. The synchronous base reasons were already evaluated
  // against the original input by `inspect()`; each structured finding above is
  // evaluated separately against its OUTCOME subject. This prevents an
  // allowlist for the original host from suppressing a discovered destination.
  // The `suppression` marker already rides on base.checksRun.
  const reasons: Reason[] = [...base.reasons, ...enrichmentReasons];
  reasons.sort(compareReasons);

  const confusables: Confusable[] = [
    ...base.confusables,
    ...enrichmentFindings.flatMap(({ finding }) => finding.confusables ?? []),
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
    ...enrichmentFindings.map(({ finding }) => finding.confidence ?? 1),
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

/**
 * Execute a caller-ordered dependency plan without allowing completion timing to
 * affect serialized order. Root/independent steps share a stage and run through
 * `Promise.all`; a later step is admitted only after every declared prerequisite
 * has wholly completed (`success`/`no-hit`).
 */
async function executeEnrichmentPlan(
  plan: EnrichmentPlan,
  base: InspectResult,
  signal: AbortSignal | undefined,
  cache: EnrichmentCache | undefined,
  governor: EnrichmentGovernor | undefined,
): Promise<EnricherRun[]> {
  const steps: PlannedEnricher[] = plan.map((enricher, index) => {
    const rawDependencies: unknown = enricher.dependsOn;
    const dependencyShapeValid =
      rawDependencies === undefined ||
      (Array.isArray(rawDependencies) &&
        rawDependencies.every(
          (dependency) => typeof dependency === "string" && dependency.trim() !== "",
        ));
    const dependencies =
      dependencyShapeValid && Array.isArray(rawDependencies)
        ? [...new Set(rawDependencies as readonly string[])]
        : [];
    return {
      index,
      token: checkToken(enricher),
      enricher,
      dependencies,
      dependencyShapeValid,
    };
  });

  const tokenCounts = new Map<string, number>();
  for (const step of steps) {
    tokenCounts.set(step.token, (tokenCounts.get(step.token) ?? 0) + 1);
  }
  const tokenToIndex = new Map<string, number>();
  for (const step of steps) {
    if (tokenCounts.get(step.token) === 1) tokenToIndex.set(step.token, step.index);
  }

  const runs: Array<EnricherRun | undefined> = new Array(steps.length);
  const pending = new Set<number>();

  // Preflight errors are explicit skipped outcomes. They are framework/config
  // states, not provider failures and certainly not benign or malicious verdicts.
  for (const step of steps) {
    let details: EnrichmentPayload | null = null;
    if ((tokenCounts.get(step.token) ?? 0) > 1) {
      details = { reason: "duplicate-check-token", token: step.token };
    } else if (!step.dependencyShapeValid) {
      details = { reason: "invalid-prerequisite-token" };
    } else {
      const unknown = step.dependencies.filter(
        (dependency) => !tokenToIndex.has(dependency),
      );
      if (unknown.length > 0) {
        details = { reason: "unknown-prerequisite", prerequisites: unknown };
      }
    }

    if (details !== null) {
      runs[step.index] = {
        token: step.token,
        report: frameworkReport(
          step.enricher,
          base,
          "skipped",
          "invalid-plan",
          false,
          details,
        ),
      };
    } else {
      pending.add(step.index);
    }
  }

  while (pending.size > 0) {
    // Cancellation is the direct cause for every not-yet-started step. Do not
    // relabel it as a prerequisite failure merely because an earlier step also
    // observed the same cancellation.
    if (signal?.aborted) {
      for (const index of pending) {
        const step = steps[index]!;
        runs[index] = {
          token: step.token,
          report: frameworkReport(
            step.enricher,
            base,
            "skipped",
            "caller-aborted",
            false,
          ),
        };
      }
      pending.clear();
      break;
    }

    const ready = [...pending].filter((index) => {
      const step = steps[index]!;
      return step.dependencies.every((dependency) => {
        const dependencyIndex = tokenToIndex.get(dependency);
        const dependencyRun =
          dependencyIndex === undefined ? undefined : runs[dependencyIndex];
        return dependencyRun !== undefined && runIsAvailable(dependencyRun);
      });
    });

    if (ready.length > 0) {
      const previousOutcomes = Object.freeze(
        runs.flatMap((run) => run?.report.outcomes ?? []),
      );
      const ctx: EnrichmentContext = {
        ...(signal !== undefined ? { signal } : {}),
        previousOutcomes,
      };
      const stageRuns = await Promise.all(
        ready.map((index) =>
          runEnricher(steps[index]!.enricher, base, ctx, cache, governor),
        ),
      );
      for (let offset = 0; offset < ready.length; offset += 1) {
        const index = ready[offset]!;
        runs[index] = stageRuns[offset]!;
        pending.delete(index);
      }
      continue;
    }

    const blocked = [...pending].filter((index) => {
      const step = steps[index]!;
      return step.dependencies.some((dependency) => {
        const dependencyIndex = tokenToIndex.get(dependency);
        const dependencyRun =
          dependencyIndex === undefined ? undefined : runs[dependencyIndex];
        return dependencyRun !== undefined && !runIsAvailable(dependencyRun);
      });
    });

    if (blocked.length > 0) {
      for (const index of blocked) {
        const step = steps[index]!;
        const unavailable = step.dependencies.filter((dependency) => {
          const dependencyIndex = tokenToIndex.get(dependency);
          const dependencyRun =
            dependencyIndex === undefined ? undefined : runs[dependencyIndex];
          return dependencyRun !== undefined && !runIsAvailable(dependencyRun);
        });
        runs[index] = {
          token: step.token,
          report: frameworkReport(
            step.enricher,
            base,
            "skipped",
            "prerequisite-unavailable",
            false,
            { prerequisites: unavailable },
          ),
        };
        pending.delete(index);
      }
      continue;
    }

    // With no ready or blocked node, the remaining graph contains a cycle. Mark
    // only one actual cycle per pass; nodes downstream of it then receive the
    // truthful `prerequisite-unavailable` state on the next pass.
    const cycle = findDependencyCycle(pending, steps, tokenToIndex);
    const cycleIndexes = cycle.length > 0 ? cycle : [[...pending][0]!];
    for (const index of cycleIndexes) {
      const step = steps[index]!;
      runs[index] = {
        token: step.token,
        report: frameworkReport(
          step.enricher,
          base,
          "skipped",
          "dependency-cycle",
          false,
          { prerequisites: [...step.dependencies] },
        ),
      };
      pending.delete(index);
    }
  }

  // Every slot is settled above. The defensive fallback keeps this total even
  // if a future plan branch is added incorrectly, while preserving plan order.
  return steps.map((step) =>
    runs[step.index] ?? {
      token: step.token,
      report: frameworkReport(
        step.enricher,
        base,
        "skipped",
        "invalid-plan",
        false,
        { reason: "unsettled-plan-node" },
      ),
    },
  );
}

function checkToken(enricher: Enricher): string {
  return `${enricher.layer}:${enricher.id}`;
}

function runIsAvailable(run: EnricherRun): boolean {
  return run.report.outcomes.every(
    (outcome) => outcome.status === "success" || outcome.status === "no-hit",
  );
}

/** Find one dependency cycle among pending plan nodes, preserving plan order. */
function findDependencyCycle(
  pending: ReadonlySet<number>,
  steps: readonly PlannedEnricher[],
  tokenToIndex: ReadonlyMap<string, number>,
): number[] {
  const state = new Map<number, "visiting" | "visited">();
  const stack: number[] = [];

  const visit = (index: number): number[] | null => {
    state.set(index, "visiting");
    stack.push(index);
    for (const dependency of steps[index]!.dependencies) {
      const dependencyIndex = tokenToIndex.get(dependency);
      if (dependencyIndex === undefined || !pending.has(dependencyIndex)) continue;
      if (state.get(dependencyIndex) === "visiting") {
        return stack.slice(stack.indexOf(dependencyIndex));
      }
      if (state.get(dependencyIndex) === undefined) {
        const found = visit(dependencyIndex);
        if (found !== null) return found;
      }
    }
    stack.pop();
    state.set(index, "visited");
    return null;
  };

  for (const index of pending) {
    if (state.get(index) !== undefined) continue;
    const found = visit(index);
    if (found !== null) return found;
  }
  return [];
}

/** Race sentinel: the bounded timeout fired (or the caller's signal aborted). */
const TIMED_OUT = Symbol("timed-out");

/** Schema-scoped prefix for opaque store keys; caller key material is never derived by core. */
const ENRICHMENT_CACHE_NAMESPACE = `linklint:enrichment:${ENRICHMENT_SCHEMA_VERSION}`;

/** A framework-owned operational degradation collected around one source run. */
interface RuntimeDegradation {
  status: "skipped" | "failure";
  code: EnrichmentFrameworkCauseCode;
  retryable: boolean;
  details?: EnrichmentPayload;
}

/**
 * Run a single enricher behind a total guard. This function is the isolation
 * boundary for caller/provider code and every pluggable cache/governor method;
 * none of those exceptions may reject the aggregate inspection.
 *
 * Ordering remains cache-before-governor. A usable hit performs no admission or
 * network work. A miss is optionally admitted, then the provider call is always
 * raced against a hard deadline (the 5s runner default, a positive finite
 * per-source/governor override, or an explicit `null` opt-out). Auxiliary
 * infrastructure failures are retained as additional attributed outcomes when
 * the provider can still run, so successful evidence is not silently discarded.
 */
async function runEnricher(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
  cache: EnrichmentCache | undefined,
  governor: EnrichmentGovernor | undefined,
): Promise<EnricherRun> {
  const token = `${enricher.layer}:${enricher.id}`;
  const degradations: RuntimeDegradation[] = [];

  // A signal already aborted before we start: skip without touching cache or
  // governor, and without invoking caller/provider code.
  if (ctx.signal?.aborted) {
    return {
      token,
      report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
    };
  }

  // Resolve the optional cache slot. cacheKey is caller code and therefore part
  // of the total boundary: a throw/invalid return disables caching for this run
  // and remains machine-visible while the source is still allowed to run fresh.
  let slot: CacheSlot | null = null;
  if (cache !== undefined) {
    const resolved = cacheSlotFor(enricher, base, ctx, cache);
    slot = resolved.slot;
    if (resolved.degradation !== undefined) degradations.push(resolved.degradation);
  }

  if (slot !== null) {
    let cached: unknown;
    try {
      const cacheRead = await runBoundedOperation(
        () => slot.cache.get(slot.key),
        ctx.signal,
        effectiveTimeoutMs(enricher.timeoutMs, undefined),
      );
      if (cacheRead === TIMED_OUT) {
        if (ctx.signal?.aborted) {
          return {
            token,
            report: frameworkReport(enricher, base, "skipped", "caller-aborted", false),
          };
        }
        degradations.push({
          status: "failure",
          code: "cache-read-error",
          retryable: true,
          details: { reason: "timeout" },
        });
      } else {
        cached = cacheRead;
      }
    } catch {
      degradations.push({
        status: "failure",
        code: "cache-read-error",
        retryable: true,
      });
    }

    // Cache HIT: a successful prior run stands in for this one. It still counts
    // as run. Invalid cache data is never trusted or silently treated as a miss.
    if (cached !== undefined) {
      const cachedReport = normalizeCachedReport(cached, enricher);
      return {
        token,
        report: withDegradations(
          cachedReport ??
            frameworkReport(enricher, base, "failure", "invalid-cached-output", false),
          enricher,
          base,
          degradations,
        ),
      };
    }
  }

  // Cache MISS: consult the optional stateful governor. A broken/invalid
  // admission decision fails this source closed, but cannot affect its siblings.
  let governorTimeoutMs: number | null | undefined;
  if (governor !== undefined) {
    let decision: GovernorDecision;
    try {
      const candidate: unknown = governor.admit(token);
      if (!isGovernorDecision(candidate)) {
        return {
          token,
          report: withDegradations(
            frameworkReport(enricher, base, "failure", "governor-error", true, {
              operation: "admit",
              reason: "invalid-decision",
            }),
            enricher,
            base,
            degradations,
          ),
        };
      }
      decision = candidate;
    } catch {
      return {
        token,
        report: withDegradations(
          frameworkReport(enricher, base, "failure", "governor-error", true, {
            operation: "admit",
          }),
          enricher,
          base,
          degradations,
        ),
      };
    }

    if (!decision.run) {
      return {
        token,
        report: withDegradations(
          frameworkReport(
            enricher,
            base,
            "skipped",
            decision.cause ?? "governor-denied",
            true,
          ),
          enricher,
          base,
          degradations,
        ),
      };
    }
    governorTimeoutMs = decision.timeoutMs;
  }

  const timeoutMs = effectiveTimeoutMs(enricher.timeoutMs, governorTimeoutMs);
  let output: EnricherOutput | typeof TIMED_OUT;
  try {
    output = await runWithTimeout(enricher, base, ctx, timeoutMs);
  } catch {
    addGovernorRecordDegradation(degradations, governor, "recordFailure", token);
    const primary = ctx.signal?.aborted
      ? frameworkReport(enricher, base, "skipped", "caller-aborted", false)
      : frameworkReport(enricher, base, "failure", "source-error", true);
    return {
      token,
      report: withDegradations(primary, enricher, base, degradations),
    };
  }

  if (output === TIMED_OUT) {
    addGovernorRecordDegradation(degradations, governor, "recordFailure", token);
    const primary = ctx.signal?.aborted
      ? frameworkReport(enricher, base, "skipped", "caller-aborted", false)
      : frameworkReport(enricher, base, "failure", "timeout", true);
    return {
      token,
      report: withDegradations(primary, enricher, base, degradations),
    };
  }

  // A completion observed after caller cancellation remains a skip even when the
  // provider ignored its signal. It is never cached and feeds governor backoff.
  if (ctx.signal?.aborted) {
    addGovernorRecordDegradation(degradations, governor, "recordFailure", token);
    return {
      token,
      report: withDegradations(
        frameworkReport(enricher, base, "skipped", "caller-aborted", false),
        enricher,
        base,
        degradations,
      ),
    };
  }

  const report = normalizeOutput(output, enricher, base);
  if (report === null) {
    addGovernorRecordDegradation(degradations, governor, "recordFailure", token);
    return {
      token,
      report: withDegradations(
        frameworkReport(enricher, base, "failure", "invalid-output", false),
        enricher,
        base,
        degradations,
      ),
    };
  }

  // A source-declared failure feeds backoff; successful/no-hit/skipped reports
  // are clean protocol completions. Every lifecycle callback is guarded too.
  addGovernorRecordDegradation(
    degradations,
    governor,
    report.outcomes.some((item) => item.status === "failure")
      ? "recordFailure"
      : "recordSuccess",
    token,
  );

  // Only wholly completed success/no-hit reports are cache candidates. No-hit is
  // an explicit negative result and may use a shorter response-derived TTL. A
  // resolver/write failure does not erase valid source evidence, but remains a
  // failure outcome and prevents a dependent stage from mistaking this partially
  // degraded run for wholly clean.
  if (
    slot !== null &&
    report.outcomes.every((item) => item.status === "success" || item.status === "no-hit")
  ) {
    const ttl = cacheTtlFor(enricher, report, ctx, slot.staticTtlMs);
    if (ttl.degradation !== undefined) degradations.push(ttl.degradation);
    const ttlMs = ttl.ttlMs;
    if (ttlMs !== null) {
      try {
        const cacheWrite = await runBoundedOperation(
          () => slot.cache.set(slot.key, cloneEnrichmentReport(report), ttlMs),
          ctx.signal,
          effectiveTimeoutMs(enricher.timeoutMs, undefined),
        );
        if (cacheWrite === TIMED_OUT) {
          degradations.push({
            status: "failure",
            code: "cache-write-error",
            retryable: true,
            details: {
              reason: ctx.signal?.aborted ? "caller-aborted" : "timeout",
            },
          });
        }
      } catch {
        degradations.push({
          status: "failure",
          code: "cache-write-error",
          retryable: true,
        });
      }
    }
  }

  return {
    token,
    report: withDegradations(report, enricher, base, degradations),
  };
}

/** Positive finite overrides win; `null` is the only way to disable the hard bound. */
function effectiveTimeoutMs(
  enricherTimeoutMs: number | null | undefined,
  governorTimeoutMs: number | null | undefined,
): number | undefined {
  if (enricherTimeoutMs === null) return undefined;
  if (isPositiveFinite(enricherTimeoutMs)) return enricherTimeoutMs;
  if (governorTimeoutMs === null) return undefined;
  if (isPositiveFinite(governorTimeoutMs)) return governorTimeoutMs;
  return DEFAULT_ENRICHMENT_TIMEOUT_MS;
}

function isPositiveFinite(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

/** Runtime guard for untrusted custom governor decisions. */
function isGovernorDecision(value: unknown): value is GovernorDecision {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const decision = value as Record<string, unknown>;
  if (decision.run === false) {
    return (
      decision.cause === undefined ||
      decision.cause === "rate-limited" ||
      decision.cause === "backoff-active"
    );
  }
  if (decision.run !== true) return false;
  return (
    decision.timeoutMs === undefined ||
    decision.timeoutMs === null ||
    typeof decision.timeoutMs === "number"
  );
}

/** Guard a governor lifecycle callback and retain a machine-readable failure. */
function addGovernorRecordDegradation(
  degradations: RuntimeDegradation[],
  governor: EnrichmentGovernor | undefined,
  operation: "recordSuccess" | "recordFailure",
  token: string,
): void {
  if (governor === undefined) return;
  try {
    governor[operation](token);
  } catch {
    degradations.push({
      status: "failure",
      code: "governor-error",
      retryable: true,
      details: { operation },
    });
  }
}

/** Add framework-owned runtime outcomes after the source's own stable output. */
function withDegradations(
  report: EnrichmentReport,
  enricher: Enricher,
  base: InspectResult,
  degradations: readonly RuntimeDegradation[],
): EnrichmentReport {
  if (degradations.length === 0) return report;
  return {
    schemaVersion: ENRICHMENT_SCHEMA_VERSION,
    outcomes: [
      ...report.outcomes,
      ...degradations.flatMap(
        (degradation) =>
          frameworkReport(
            enricher,
            base,
            degradation.status,
            degradation.code,
            degradation.retryable,
            degradation.details,
          ).outcomes,
      ),
    ],
  };
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
 * An unbounded call exists only after the explicit `null` timeout policy resolves
 * to `undefined`. A caller signal is always raced, so cancellation also settles
 * an enricher that ignores it.
 */
async function runWithTimeout(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
  timeoutMs: number | undefined,
): Promise<EnricherOutput | typeof TIMED_OUT> {
  const hasTimeout =
    timeoutMs !== undefined && Number.isFinite(timeoutMs) && timeoutMs > 0;
  if (!hasTimeout && ctx.signal === undefined) {
    return enricher.enrich(base, ctx);
  }

  const timeoutController = hasTimeout ? new AbortController() : null;
  const timer =
    timeoutController === null
      ? null
      : setTimeout(() => timeoutController.abort(), timeoutMs);
  const signals = [
    ...(ctx.signal !== undefined ? [ctx.signal] : []),
    ...(timeoutController !== null ? [timeoutController.signal] : []),
  ];
  const composed = signals.length === 1 ? signals[0]! : AbortSignal.any(signals);
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
    if (timer !== null) clearTimeout(timer);
  }
}

/**
 * Await a synchronous or Promise-capable infrastructure operation behind the
 * same safe source deadline used for provider work. `Promise.race` keeps the
 * abandoned operation observed, so a late external-store rejection is handled.
 */
async function runBoundedOperation<T>(
  operation: () => T | PromiseLike<T>,
  signal: AbortSignal | undefined,
  timeoutMs: number | undefined,
): Promise<T | typeof TIMED_OUT> {
  if (signal?.aborted) return TIMED_OUT;
  const hasTimeout =
    timeoutMs !== undefined && Number.isFinite(timeoutMs) && timeoutMs > 0;
  if (!hasTimeout && signal === undefined) return await operation();

  const timeoutController = hasTimeout ? new AbortController() : null;
  const timer =
    timeoutController === null
      ? null
      : setTimeout(() => timeoutController.abort(), timeoutMs);
  const signals = [
    ...(signal !== undefined ? [signal] : []),
    ...(timeoutController !== null ? [timeoutController.signal] : []),
  ];
  const composed = signals.length === 1 ? signals[0]! : AbortSignal.any(signals);
  const timeoutRace = new Promise<typeof TIMED_OUT>((resolve) => {
    if (composed.aborted) {
      resolve(TIMED_OUT);
      return;
    }
    composed.addEventListener("abort", () => resolve(TIMED_OUT), { once: true });
  });
  const operationPromise = Promise.resolve().then(operation);

  try {
    return await Promise.race([operationPromise, timeoutRace]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/** Validate structured output or adapt a legacy findings array without inventing provenance. */
function normalizeOutput(
  output: unknown,
  enricher: Enricher,
  base: InspectResult,
): EnrichmentReport | null {
  if (isEnricherFindingArray(output)) {
    return cloneEnrichmentReport(legacyReport(enricher, base, output));
  }
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
  return cloneEnrichmentReport(output);
}

/**
 * Validate untrusted cached data. K9 stores only normalized reports, never raw
 * legacy arrays. Declared provider provenance and core's legacy compatibility
 * provenance are both cacheable; framework-unavailable outcomes are not.
 */
function normalizeCachedReport(
  output: unknown,
  enricher: Enricher,
): EnrichmentReport | null {
  if (!isEnrichmentReport(output, { sourceId: enricher.id, layer: enricher.layer })) {
    return null;
  }
  for (const outcome of output.outcomes) {
    if (outcome.provenance.kind === "unavailable") return null;
    if (
      outcome.evidence.some(
        (evidence) => evidence.provenance.kind !== outcome.provenance.kind,
      )
    ) {
      return null;
    }
  }
  return cloneEnrichmentReport(output);
}

/** Detach validated JSON-safe data from caller/store-owned mutable references. */
function cloneEnrichmentReport(report: EnrichmentReport): EnrichmentReport {
  return JSON.parse(JSON.stringify(report)) as EnrichmentReport;
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
  code: EnrichmentFrameworkCauseCode,
  retryable: boolean,
  details?: EnrichmentPayload,
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
        cause: { code, retryable, ...(details !== undefined ? { details } : {}) },
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

/** A resolved cache slot: the store, opaque namespaced key, and static fallback TTL. */
interface CacheSlot {
  cache: EnrichmentCache;
  key: string;
  staticTtlMs: number | undefined;
}

interface CacheSlotResolution {
  slot: CacheSlot | null;
  degradation?: RuntimeDegradation;
}

/**
 * Resolve an enricher's cache slot for this inspection. An enricher is cacheable
 * only when it declares a `cacheKey` that returns a non-null string AND either a
 * positive, finite static `cacheTtlMs` or a dynamic `cacheTtlMsFor` resolver — a
 * missing TTL policy degrades to "run fresh every call", never to a guessed
 * default.
 *
 * The returned key is an opaque JSON tuple namespaced by schema version and the
 * enricher's `<layer>:<id>` check token, so two sources and incompatible report
 * schemas cannot collide. `cacheKey` is caller code, so throws, invalid/empty
 * returns, and direct raw-URL leakage are exposed as `cache-key-error` while the
 * provider proceeds uncached.
 */
function cacheSlotFor(
  enricher: Enricher,
  base: InspectResult,
  ctx: EnrichmentContext,
  cache: EnrichmentCache,
): CacheSlotResolution {
  if (typeof enricher.cacheKey !== "function") return { slot: null };
  const staticTtlMs = isPositiveFinite(enricher.cacheTtlMs)
    ? enricher.cacheTtlMs
    : undefined;
  const rawDynamicTtl: unknown = enricher.cacheTtlMsFor;
  if (rawDynamicTtl !== undefined && typeof rawDynamicTtl !== "function") {
    return {
      slot: null,
      degradation: {
        status: "failure",
        code: "cache-ttl-error",
        retryable: false,
        details: { reason: "invalid-resolver" },
      },
    };
  }
  if (staticTtlMs === undefined && rawDynamicTtl === undefined) {
    return { slot: null };
  }
  let key: unknown;
  try {
    key = enricher.cacheKey(base, ctx);
  } catch {
    return {
      slot: null,
      degradation: {
        status: "failure",
        code: "cache-key-error",
        retryable: false,
        details: { reason: "threw" },
      },
    };
  }
  if (key === null || key === undefined) return { slot: null };
  if (typeof key !== "string" || key.length === 0) {
    return {
      slot: null,
      degradation: {
        status: "failure",
        code: "cache-key-error",
        retryable: false,
        details: { reason: "invalid-return" },
      },
    };
  }
  const subject = inspectionSubject(base);
  if (subject.kind === "url" && base.input.length > 0 && key.includes(base.input)) {
    return {
      slot: null,
      degradation: {
        status: "failure",
        code: "cache-key-error",
        retryable: false,
        details: { reason: "unsafe-full-url" },
      },
    };
  }
  return {
    slot: {
      cache,
      key: JSON.stringify([
        ENRICHMENT_CACHE_NAMESPACE,
        `${enricher.layer}:${enricher.id}`,
        key,
      ]),
      staticTtlMs,
    },
  };
}

interface CacheTtlResolution {
  ttlMs: number | null;
  degradation?: RuntimeDegradation;
}

/** Resolve the dynamic per-entry TTL, falling back to the legacy static value. */
function cacheTtlFor(
  enricher: Enricher,
  report: EnrichmentReport,
  ctx: EnrichmentContext,
  staticTtlMs: number | undefined,
): CacheTtlResolution {
  let candidate: unknown = undefined;
  if (typeof enricher.cacheTtlMsFor === "function") {
    try {
      candidate = enricher.cacheTtlMsFor(cloneEnrichmentReport(report), ctx);
    } catch {
      return {
        ttlMs: null,
        degradation: {
          status: "failure",
          code: "cache-ttl-error",
          retryable: false,
          details: { reason: "threw" },
        },
      };
    }
  }
  if (candidate === undefined) candidate = staticTtlMs;
  if (candidate === null || candidate === undefined) return { ttlMs: null };
  if (typeof candidate !== "number") {
    return {
      ttlMs: null,
      degradation: {
        status: "failure",
        code: "cache-ttl-error",
        retryable: false,
        details: { reason: "invalid-return" },
      },
    };
  }
  return { ttlMs: isPositiveFinite(candidate) ? candidate : null };
}
