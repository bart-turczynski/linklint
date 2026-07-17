/**
 * Per-source governor for async enrichers (LINK-bergliii, unit K4).
 *
 * Networked enrichers (roadmap resolution/reputation layers — docs/architecture.md
 * §10) talk to third parties that can be slow, flaky, or rate-limited. This module
 * gives the async pipeline a pluggable, per-source *governor* that enforces three
 * mechanisms — a bounded timeout, a token-bucket rate limit, and exponential
 * backoff — so that **one slow or failing source can never block a verdict**. A
 * governed source that is over budget, spent, or in an open backoff window
 * degrades to `checksSkipped` (`<layer>:<id>`); the rest of the enrichers and the
 * lexical verdict proceed unchanged. This extends the K1 graceful-degradation
 * guarantee.
 *
 * Design (mirrors the K3 cache in `enrichment-cache.ts`):
 *  - **Opt-in.** The governor is nothing until a caller supplies one via
 *    `inspectAsync(..., { governor })`. With no governor the pipeline behaves
 *    exactly as K1/K2/K3 — none of the three mechanisms engage. Governance is NOT
 *    on by default.
 *  - **Per-source.** All state is keyed by the enricher's `<layer>:<id>` check
 *    token, so each source has an independent token bucket and backoff schedule.
 *  - **Injectable clock.** `InMemoryEnrichmentGovernor` takes a `now` function so
 *    rate-limit refill and backoff windows can be driven deterministically in
 *    tests without real wall-clock sleeps; it defaults to `Date.now`.
 *  - **State persists across `inspectAsync` calls** — share one instance to make
 *    the rate limit and backoff meaningful across inspections.
 *
 * The bounded-timeout *value* lives here (a governor default, overridable per
 * enricher via `Enricher.timeoutMs`); the actual timeout race / abort composition
 * is orchestration and lives in `inspect-async.ts`.
 *
 * Not here (clean seam for K5): allowlist / feedback. This module is
 * dependency-free.
 */

/**
 * The governor's verdict for a single enricher, returned by {@link EnrichmentGovernor.admit}.
 *
 *  - `{ run: false }` — SKIP: the source is rate-limited (no token available) or in
 *    an open backoff window. `enrich` MUST NOT be called; nothing is consumed.
 *  - `{ run: true, timeoutMs? }` — ADMITTED: a rate-limit token has been consumed
 *    and the caller should run `enrich` bounded by `timeoutMs` (a positive, finite
 *    ms budget, or `undefined` for "no bound"). An enricher's own `timeoutMs` takes
 *    precedence over this default.
 */
export type GovernorDecision = { run: false } | { run: true; timeoutMs?: number };

/**
 * A pluggable per-source policy the async pipeline consults on a cache MISS,
 * before running an enricher. Implementations must be side-effect-safe: none of
 * these methods may throw (a throwing governor is a programming error, not a
 * handled degradation path).
 *
 * Lifecycle per governed enricher run (see `inspect-async.ts`):
 *  1. {@link admit} is called exactly once. On `{ run: true }` a token is consumed;
 *     on `{ run: false }` the enricher is skipped without invoking it.
 *  2. If admitted, exactly one of {@link recordSuccess} / {@link recordFailure} is
 *     called with the outcome — success resets backoff, failure opens/extends it.
 */
export interface EnrichmentGovernor {
  /**
   * Consult the governor for `token` (`<layer>:<id>`). Called only on a cache MISS,
   * after the abort check. A `{ run: true }` decision CONSUMES one rate-limit token
   * — that is the single, precise moment a token is spent (an *attempted* run, not
   * a cache hit or a skip). A `{ run: false }` decision consumes nothing.
   */
  admit(token: string): GovernorDecision;
  /**
   * Record that an admitted run for `token` succeeded. Resets the source's
   * consecutive-failure count and clears any open backoff window.
   */
  recordSuccess(token: string): void;
  /**
   * Record that an admitted run for `token` did NOT cleanly succeed — a timeout,
   * a throw/reject, an observed post-abort, a source-declared failure, or an
   * invalid legacy/structured return.
   * Increments the consecutive-failure count and opens an exponentially larger
   * backoff window.
   */
  recordFailure(token: string): void;
}

/** Tunable policy for {@link InMemoryEnrichmentGovernor}. All fields optional. */
export interface EnrichmentGovernorConfig {
  /** Injectable clock (epoch-ms). Defaults to {@link Date.now}. */
  now?: () => number;
  /**
   * Default bounded timeout (ms) returned in an admit decision. `enrich` is raced
   * against this unless the enricher declares its own `timeoutMs`. A non-positive
   * or non-finite value means "no default bound". Default: 5000.
   */
  defaultTimeoutMs?: number;
  /**
   * Token-bucket capacity per source: the maximum burst of admitted runs, and the
   * value each bucket starts full at. Default: 10.
   */
  capacity?: number;
  /**
   * Token-bucket refill: one token is regained every `refillIntervalMs`
   * (continuous fractional accrual, capped at `capacity`). Default: 1000 (one
   * token per second). A non-positive/non-finite value disables refill (the
   * initial `capacity` tokens are all a source ever gets).
   */
  refillIntervalMs?: number;
  /**
   * First backoff window (ms), opened after a source's first consecutive failure.
   * Each further consecutive failure doubles it, capped at `backoffMaxMs`.
   * Default: 1000.
   */
  backoffBaseMs?: number;
  /** Cap on the backoff window (ms). Default: 30000. */
  backoffMaxMs?: number;
}

/** Per-source mutable state: token bucket + backoff schedule. */
interface SourceState {
  /** Current (fractional) token count. */
  tokens: number;
  /** Epoch-ms of the last refill accrual, used to compute elapsed refill. */
  lastRefill: number;
  /** Count of consecutive failures with no intervening success (drives backoff). */
  consecutiveFailures: number;
  /** Epoch-ms until which the source is in an open backoff window (0 = none). */
  backoffUntil: number;
}

const DEFAULTS = {
  defaultTimeoutMs: 5000,
  capacity: 10,
  refillIntervalMs: 1000,
  backoffBaseMs: 1000,
  backoffMaxMs: 30000,
} as const;

/**
 * The default, dependency-free {@link EnrichmentGovernor}: an in-memory `Map` of
 * per-source token buckets and backoff schedules, driven by an injectable clock.
 *
 * Semantics:
 *  - **Bounded timeout** — {@link admit} returns the effective default `timeoutMs`;
 *    the pipeline races `enrich` against it (enricher override wins). The race is
 *    a HARD guarantee: even an enricher that ignores its abort signal cannot stall
 *    the verdict past the timeout.
 *  - **Rate limit** — a per-source token bucket (capacity + continuous refill). A
 *    token is consumed on each `admit` that returns `{ run: true }`. When the
 *    bucket is empty the source is SKIPPED — never queued or blocked.
 *  - **Backoff** — after N consecutive failures the source is skipped WITHOUT
 *    calling `enrich` until `now >= backoffUntil`. The window grows exponentially
 *    (`backoffBaseMs * 2^(N-1)`, capped at `backoffMaxMs`) and RESETS on the first
 *    success.
 *
 * Ordering inside {@link admit}: backoff is checked FIRST (a backed-off source is
 * skipped without spending a token), then the token bucket.
 */
export class InMemoryEnrichmentGovernor implements EnrichmentGovernor {
  private readonly states = new Map<string, SourceState>();
  private readonly now: () => number;
  private readonly defaultTimeoutMs: number;
  private readonly capacity: number;
  private readonly refillIntervalMs: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;

  constructor(config: EnrichmentGovernorConfig = {}) {
    this.now = config.now ?? Date.now;
    this.defaultTimeoutMs = config.defaultTimeoutMs ?? DEFAULTS.defaultTimeoutMs;
    this.capacity = positiveOr(config.capacity, DEFAULTS.capacity);
    this.refillIntervalMs = config.refillIntervalMs ?? DEFAULTS.refillIntervalMs;
    this.backoffBaseMs = positiveOr(config.backoffBaseMs, DEFAULTS.backoffBaseMs);
    this.backoffMaxMs = positiveOr(config.backoffMaxMs, DEFAULTS.backoffMaxMs);
  }

  admit(token: string): GovernorDecision {
    const now = this.now();
    const state = this.stateFor(token, now);

    // Backoff FIRST: a source in an open window is skipped without spending a
    // token — there is no point charging a call we will not make.
    if (state.backoffUntil > now) return { run: false };

    // Then the token bucket: refill by elapsed time, then try to spend one.
    this.refill(state, now);
    if (state.tokens < 1) return { run: false };
    state.tokens -= 1;

    const timeoutMs =
      Number.isFinite(this.defaultTimeoutMs) && this.defaultTimeoutMs > 0
        ? this.defaultTimeoutMs
        : undefined;
    return timeoutMs !== undefined ? { run: true, timeoutMs } : { run: true };
  }

  recordSuccess(token: string): void {
    const state = this.stateFor(token, this.now());
    state.consecutiveFailures = 0;
    state.backoffUntil = 0;
  }

  recordFailure(token: string): void {
    const now = this.now();
    const state = this.stateFor(token, now);
    state.consecutiveFailures += 1;
    // window = base * 2^(failures-1), capped. First failure → base, then doubling.
    const raw = this.backoffBaseMs * 2 ** (state.consecutiveFailures - 1);
    const window = Math.min(raw, this.backoffMaxMs);
    state.backoffUntil = now + window;
  }

  /** Fetch (or lazily create, starting full) the state for a source. */
  private stateFor(token: string, now: number): SourceState {
    let state = this.states.get(token);
    if (state === undefined) {
      state = { tokens: this.capacity, lastRefill: now, consecutiveFailures: 0, backoffUntil: 0 };
      this.states.set(token, state);
    }
    return state;
  }

  /** Accrue tokens for the elapsed interval, capped at capacity. */
  private refill(state: SourceState, now: number): void {
    if (!Number.isFinite(this.refillIntervalMs) || this.refillIntervalMs <= 0) {
      // Refill disabled: only the initial capacity is ever available.
      state.lastRefill = now;
      return;
    }
    const elapsed = now - state.lastRefill;
    if (elapsed <= 0) return;
    state.tokens = Math.min(this.capacity, state.tokens + elapsed / this.refillIntervalMs);
    state.lastRefill = now;
  }
}

/** A finite, positive number, or the fallback. */
function positiveOr(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
}
