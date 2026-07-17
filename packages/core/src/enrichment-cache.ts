/**
 * Result cache for async enrichers (LINK-wtnpkbkf, unit K3).
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
 *  - **Per-source TTL.** TTL is carried per `set()` call, sourced from each
 *    enricher's own `cacheTtlMs` (see {@link import("./schema/enrich.js").Enricher}).
 *    Two enrichers therefore expire independently — that is what "per-source TTLs"
 *    means.
 *  - **Privacy.** The cache key is ENTIRELY enricher-supplied (an enricher's
 *    `cacheKey(result)`); the framework never derives a key from the full URL. See
 *    the `cacheKey` contract in `schema/enrich.ts`.
 *
 * Not here (clean seams): rate-limit / backoff / timeout live in
 * `enrichment-governor.ts` (K4); allowlist / feedback (K5). This module is
 * dependency-free.
 */

import type { EnricherFinding } from "./schema/enrich.js";

/**
 * A pluggable store the async pipeline consults before running a cacheable
 * enricher. Implementations must be side-effect-safe: `get`/`set` MUST NOT throw
 * (a throwing store is a programming error, not a handled degradation path).
 *
 * The pipeline treats `get` returning `undefined` as "no usable entry" — both a
 * true miss AND an expired entry collapse to `undefined`, so expiry policy lives
 * entirely inside the store.
 */
export interface EnrichmentCache {
  /**
   * Look up findings previously stored under `key`. Returns `undefined` on a miss
   * OR when the stored entry has expired (the store is responsible for enforcing
   * its own TTL). A non-`undefined` return is a cache HIT and its findings flow
   * into the result exactly like freshly-computed ones.
   */
  get(key: string): EnricherFinding[] | undefined;
  /**
   * Store `findings` under `key`, valid for `ttlMs` milliseconds from now. The
   * pipeline only calls `set` after a SUCCESSFUL enricher run — failures and skips
   * are never cached. A non-positive or non-finite `ttlMs` should be treated as
   * "do not store".
   */
  set(key: string, findings: EnricherFinding[], ttlMs: number): void;
}

/** A stored entry: the cached findings plus the absolute epoch-ms it expires at. */
interface CacheEntry {
  findings: EnricherFinding[];
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

  get(key: string): EnricherFinding[] | undefined {
    const entry = this.store.get(key);
    if (entry === undefined) return undefined;
    // Lazy eviction: an expired entry is a miss, and we drop it as we notice it.
    if (this.now() >= entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.findings;
  }

  set(key: string, findings: EnricherFinding[], ttlMs: number): void {
    // A non-positive / non-finite TTL is not cacheable — refuse to store rather
    // than plant an already-dead (or immortal) entry.
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) return;
    this.store.set(key, { findings, expiresAt: this.now() + ttlMs });
  }
}
