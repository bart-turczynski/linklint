/**
 * Result cache for async enrichers (LINK-wtnpkbkf K3, LINK-xwgzgyfu K9).
 *
 * Networked enrichers (roadmap resolution/reputation layers — docs/architecture.md
 * §10) can be expensive and re-hit third parties on every call. This module gives
 * the async pipeline a pluggable, per-source result cache so a repeat inspection of
 * the same source reuses a prior enricher's findings instead of re-querying.
 *
 * Design:
 *  - **Opt-in.** The cache is nothing until a caller supplies one via
 *    `inspectAsync(..., { cache })`. With no cache the pipeline behaves exactly as
 *    K1/K2 — this mirrors K1's opt-in enricher design; caching is NOT on by default.
 *  - **Per-entry TTL.** TTL is carried per `set()` call. It may be the enricher's
 *    static `cacheTtlMs` or be derived from the validated report by
 *    `cacheTtlMsFor` (see {@link import("./schema/enrich.js").Enricher}). Positive
 *    and no-hit results can therefore use different response-driven lifetimes.
 *  - **External-store ready.** `get` and `set` may complete synchronously or return
 *    a PromiseLike. The runner awaits and guards either form.
 *  - **Privacy.** The cache key is ENTIRELY enricher-supplied (an enricher's
 *    `cacheKey(result, context)`); the framework never derives a key from the
 *    full URL. See the `cacheKey` contract in `schema/enrich.ts`.
 *
 * Not here (clean seams): rate-limit / backoff / timeout live in
 * `enrichment-governor.ts` (K4); allowlist / feedback (K5). This module is
 * dependency-free.
 */

import type { EnrichmentReport } from "./schema/enrich.js";

/** A cache operation may be implemented in-process or by an asynchronous store. */
export type EnrichmentCacheOperation<T> = T | PromiseLike<T>;

/**
 * A pluggable store the async pipeline consults before running a cacheable
 * enricher. Implementations should be side-effect-safe and not throw/reject. The
 * runner still guards and bounds both calls: an exception or rejection becomes
 * an attributed cache degradation outcome and never rejects the aggregate
 * inspection.
 *
 * The pipeline treats `get` returning `undefined` as "no usable entry" — both a
 * true miss AND an expired entry collapse to `undefined`, so expiry policy lives
 * entirely inside the store.
 */
export interface EnrichmentCache {
  /**
   * Look up a structured report previously stored under `key`. Returns
   * `undefined` on a miss OR when the stored entry has expired (the store is
   * responsible for enforcing its own TTL). A non-`undefined` return is treated
   * as untrusted input and runtime-validated before it can affect a result.
   */
  get(key: string): EnrichmentCacheOperation<EnrichmentReport | undefined>;
  /**
   * Store a runtime-validated structured `report` under `key`, valid for `ttlMs`
   * milliseconds from now. The pipeline only calls `set` for wholly completed
   * success/no-hit reports — failures, skips, and partial reports are never
   * cached. A non-positive or non-finite `ttlMs` should be treated as "do not
   * store".
   */
  set(
    key: string,
    report: EnrichmentReport,
    ttlMs: number,
  ): EnrichmentCacheOperation<void>;
}

/** A stored entry: the validated structured report plus its absolute expiry. */
interface CacheEntry {
  report: EnrichmentReport;
  expiresAt: number;
}

/**
 * The default, dependency-free {@link EnrichmentCache}: a `Map` keyed by the
 * caller-supplied key, each entry carrying an absolute expiry timestamp. Eviction
 * is LAZY — an expired entry is dropped on the `get` that observes it, not by a
 * background timer — so the store holds no timers and is safe to create per-call
 * or share across many calls.
 *
 * The clock is injectable (`now`) so callers/tests can drive TTL expiry
 * deterministically without real wall-clock sleeps; it defaults to `Date.now`.
 */
export class InMemoryEnrichmentCache implements EnrichmentCache {
  private readonly store = new Map<string, CacheEntry>();

  constructor(private readonly now: () => number = Date.now) {}

  get(key: string): EnrichmentReport | undefined {
    const entry = this.store.get(key);
    if (entry === undefined) return undefined;
    // Lazy eviction: an expired entry is a miss, and we drop it as we notice it.
    if (this.now() >= entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.report;
  }

  set(key: string, report: EnrichmentReport, ttlMs: number): void {
    // A non-positive / non-finite TTL is not cacheable — refuse to store rather
    // than plant an already-dead (or immortal) entry.
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) return;
    this.store.set(key, { report, expiresAt: this.now() + ttlMs });
  }
}
