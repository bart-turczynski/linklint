import { describe, expect, it } from "vitest";
import {
  ENRICHMENT_SCHEMA_VERSION,
  InMemoryEnrichmentCache,
  inspect,
  inspectAsync,
  type EnrichmentCache,
} from "../src/index.js";
import type {
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentLayer,
  EnrichmentReport,
  InspectResult,
} from "../src/schema/types.js";

/**
 * Contract tests for the async result cache (LINK-wtnpkbkf, unit K3).
 *
 * The cache is OPT-IN: nothing changes unless the caller supplies one AND an
 * enricher declares a `cacheKey` (+ positive `cacheTtlMs`). These tests lock:
 *   1. no-cache / no-cacheKey paths behave exactly as K1/K2;
 *   2. a HIT reuses findings WITHOUT calling `enrich`, yet still records the
 *      enricher in `checksRun` as `<layer>:<id>` (a hit is still a run);
 *   3. a MISS runs and stores; a later call within TTL is a hit;
 *   4. TTL expiry forces a re-fetch (deterministic injected clock — no sleeps);
 *   5. two enrichers with different TTLs expire independently;
 *   6. an enricher without `cacheKey` is never cached;
 *   7. a failed/skipped enricher is never cached;
 *   8. a custom (pluggable) EnrichmentCache implementation is honored.
 *
 * All enrichers are no-network test doubles returning canned findings.
 */

const BENIGN = "https://www.example.com/path";

/** A plausible L2 finding; reused so scoring/merge behaviour is exercised. */
const PRIVATE_IP_FINDING: EnricherFinding = {
  code: "ip_private",
  detail: "resolved host maps to a private/internal IP",
};

function structuredReport(
  sourceId: string,
  layer: EnrichmentLayer,
  findings: EnricherFinding[] = [PRIVATE_IP_FINDING],
): EnrichmentReport {
  return {
    schemaVersion: ENRICHMENT_SCHEMA_VERSION,
    outcomes: [
      {
        sourceId,
        layer,
        status: findings.length === 0 ? "no-hit" : "success",
        subject: { kind: "host", value: "example.com" },
        observedAt: "2026-07-17T08:30:00.000Z",
        provenance: {
          kind: "declared",
          source: { name: "cache.fixture", version: "1.0.0" },
          data: null,
        },
        freshness: {
          status: "fresh",
          expiresAt: "2026-07-17T08:35:00.000Z",
        },
        evidence: [],
        findings,
      },
    ],
  };
}

/**
 * A counting test-double enricher. Records how many times `enrich` actually ran
 * so a cache hit (which must NOT call it) is observable. Cache metadata is
 * configurable per instance; a fixed `cacheKey` (independent of the URL) keeps
 * tests deterministic while honouring the privacy constraint (never the URL).
 */
class CountingEnricher implements Enricher {
  calls = 0;
  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    private readonly findings: EnricherFinding[] = [PRIVATE_IP_FINDING],
    readonly cacheTtlMs: number = 1000,
    private readonly key: string | null = "example.com",
  ) {}
  cacheKey(_result: InspectResult): string | null {
    return this.key;
  }
  async enrich(_result: InspectResult, _ctx: EnrichmentContext): Promise<EnricherFinding[]> {
    this.calls += 1;
    return this.findings;
  }
}

/** A test double that always rejects — exercises "failures are never cached". */
class ThrowingEnricher implements Enricher {
  calls = 0;
  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    readonly cacheTtlMs = 1000,
  ) {}
  cacheKey(): string | null {
    return "example.com";
  }
  async enrich(): Promise<EnricherFinding[]> {
    this.calls += 1;
    throw new Error("boom");
  }
}

describe("enrichment cache — no-cache / no-cacheKey invariants (K1/K2 preserved)", () => {
  const urls = [BENIGN, "https://paypal.com@evil.ru/", "javascript:alert(1)", "ht!tp://%%%not a url"];

  it.each(urls)("inspectAsync(%s) still deep-equals inspect(%s) with no cache", async (url) => {
    expect(await inspectAsync(url)).toEqual(inspect(url));
  });

  it("supplying a cache but no enrichers leaves the result byte-identical", async () => {
    const cache = new InMemoryEnrichmentCache();
    expect(await inspectAsync(BENIGN, { cache, enrichers: [] })).toEqual(inspect(BENIGN));
  });

  it("an enricher WITHOUT cacheKey is never cached (runs every call)", async () => {
    const cache = new InMemoryEnrichmentCache();
    // Bare enricher: no cacheKey / cacheTtlMs at all.
    const enricher: Enricher & { calls: number } = {
      id: "dns",
      layer: "resolution",
      calls: 0,
      async enrich() {
        this.calls += 1;
        return [PRIVATE_IP_FINDING];
      },
    };
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);
  });

  it("a cacheKey WITHOUT a TTL is never cached (runs every call)", async () => {
    const cache = new InMemoryEnrichmentCache();
    // cacheKey present, cacheTtlMs deliberately omitted → not cacheable.
    const enricher: Enricher & { calls: number } = {
      id: "dns",
      layer: "resolution",
      calls: 0,
      cacheKey: () => "example.com",
      async enrich() {
        this.calls += 1;
        return [PRIVATE_IP_FINDING];
      },
    };
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);
  });

  it("a cacheKey returning null is never cached (runs every call)", async () => {
    const cache = new InMemoryEnrichmentCache();
    const enricher = new CountingEnricher("dns", "resolution", [PRIVATE_IP_FINDING], 1000, null);
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);
  });
});

describe("enrichment cache — hit reuses findings without re-running (K3)", () => {
  it("miss then hit: second call does NOT call enrich but still records the run", async () => {
    const cache = new InMemoryEnrichmentCache();
    const enricher = new CountingEnricher("dns", "resolution");

    const first = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(1); // MISS → ran
    expect(first.checksRun).toContain("resolution:dns");

    const second = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(1); // HIT → NOT re-run
    // A hit is still a check that ran, and the finding still flows through.
    expect(second.checksRun).toContain("resolution:dns");
    expect(second.checksSkipped).not.toContain("resolution");
    expect(second.reasons.some((r) => r.code === "ip_private")).toBe(true);
    // Cached findings drive scoring exactly like fresh ones.
    expect(second.score).toBeCloseTo(first.score ?? -1, 10);
  });

  it("cached findings carry confidence through the min-aggregation like fresh ones", async () => {
    const cache = new InMemoryEnrichmentCache();
    const finding: EnricherFinding = { ...PRIVATE_IP_FINDING, confidence: 0.6 };
    const enricher = new CountingEnricher("dns", "resolution", [finding]);

    const first = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    const second = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(first.confidence).toBeCloseTo(0.6, 10);
    expect(second.confidence).toBeCloseTo(0.6, 10);
  });
});

describe("enrichment cache — TTL expiry forces a re-fetch (deterministic clock)", () => {
  it("re-runs enrich once the entry has expired", async () => {
    let now = 0;
    const cache = new InMemoryEnrichmentCache(() => now);
    const enricher = new CountingEnricher("dns", "resolution", [PRIVATE_IP_FINDING], 1000);

    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(1); // MISS

    now = 999; // still within TTL
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(1); // HIT

    now = 1000; // exactly at expiry → treated as expired (>= expiresAt)
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(2); // re-fetch

    now = 1500; // fresh entry still valid
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(enricher.calls).toBe(2); // HIT again
  });
});

describe("enrichment cache — per-source TTLs are independent", () => {
  it("two enrichers with different TTLs expire on their own schedules", async () => {
    let now = 0;
    const cache = new InMemoryEnrichmentCache(() => now);
    // Distinct ids so their namespaced keys never collide even on the same key.
    const shortLived = new CountingEnricher("dns", "resolution", [PRIVATE_IP_FINDING], 100);
    const longLived = new CountingEnricher(
      "rep",
      "reputation",
      [{ code: "risky_tld", detail: "reputation signal" }],
      1000,
    );

    await inspectAsync(BENIGN, { cache, enrichers: [shortLived, longLived] });
    expect(shortLived.calls).toBe(1);
    expect(longLived.calls).toBe(1);

    now = 150; // short expired, long still valid
    await inspectAsync(BENIGN, { cache, enrichers: [shortLived, longLived] });
    expect(shortLived.calls).toBe(2); // re-fetched
    expect(longLived.calls).toBe(1); // still cached
  });

  it("two enrichers sharing the same caller key do not collide (namespaced)", async () => {
    const cache = new InMemoryEnrichmentCache();
    const a = new CountingEnricher("dns", "resolution", [PRIVATE_IP_FINDING], 1000, "shared");
    const b = new CountingEnricher(
      "rep",
      "reputation",
      [{ code: "risky_tld", detail: "reputation signal" }],
      1000,
      "shared",
    );
    const r = await inspectAsync(BENIGN, { cache, enrichers: [a, b] });
    // Both ran (no cross-contamination from the shared key) and both are visible.
    expect(a.calls).toBe(1);
    expect(b.calls).toBe(1);
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(true);
    expect(r.reasons.some((x) => x.code === "risky_tld")).toBe(true);
  });
});

describe("enrichment cache — failures are never cached", () => {
  it("a throwing enricher is skipped and re-attempted on the next call", async () => {
    const cache = new InMemoryEnrichmentCache();
    const bad = new ThrowingEnricher("flaky", "reputation");

    const first = await inspectAsync(BENIGN, { cache, enrichers: [bad] });
    expect(bad.calls).toBe(1);
    expect(first.checksSkipped).toContain("reputation:flaky");
    expect(first.checksRun).not.toContain("reputation:flaky");

    // No poisoned/negative cache entry: the next call re-attempts the enricher.
    const second = await inspectAsync(BENIGN, { cache, enrichers: [bad] });
    expect(bad.calls).toBe(2);
    expect(second.checksSkipped).toContain("reputation:flaky");
  });

  it("recovers to a cached run once a previously-failing enricher succeeds", async () => {
    const cache = new InMemoryEnrichmentCache();
    let shouldThrow = true;
    const enricher: Enricher & { calls: number } = {
      id: "dns",
      layer: "resolution",
      calls: 0,
      cacheKey: () => "example.com",
      cacheTtlMs: 1000,
      async enrich() {
        this.calls += 1;
        if (shouldThrow) throw new Error("transient");
        return [PRIVATE_IP_FINDING];
      },
    };

    await inspectAsync(BENIGN, { cache, enrichers: [enricher] }); // fails, not cached
    shouldThrow = false;
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] }); // succeeds, cached
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] }); // hit
    expect(enricher.calls).toBe(2);
  });
});

describe("enrichment cache — pluggable custom store is honored", () => {
  it("routes get/set through a caller-supplied EnrichmentCache implementation", async () => {
    const gets: string[] = [];
    const sets: Array<{ key: string; ttlMs: number }> = [];
    const backing = new Map<string, EnrichmentReport>();
    const custom: EnrichmentCache = {
      get(key) {
        gets.push(key);
        return backing.get(key);
      },
      set(key, report, ttlMs) {
        sets.push({ key, ttlMs });
        backing.set(key, report);
      },
    };

    const enricher = new CountingEnricher("dns", "resolution", [PRIVATE_IP_FINDING], 555);
    await inspectAsync(BENIGN, { cache: custom, enrichers: [enricher] });
    await inspectAsync(BENIGN, { cache: custom, enrichers: [enricher] });

    // MISS then HIT via the custom store; enrich ran exactly once.
    expect(enricher.calls).toBe(1);
    expect(gets).toHaveLength(2);
    expect(sets).toHaveLength(1);
    // The enricher's own TTL is passed through to set(), and the key is
    // namespaced by the check token (never the raw URL).
    expect(sets[0]?.ttlMs).toBe(555);
    expect(sets[0]?.key).toContain("resolution:dns");
    expect(sets[0]?.key).not.toContain(BENIGN);
    expect(backing.values().next().value).toMatchObject({
      schemaVersion: ENRICHMENT_SCHEMA_VERSION,
      outcomes: [{ sourceId: "dns", layer: "resolution" }],
    });
  });

  it("awaits a Promise-capable external-store double and stores only normalized reports", async () => {
    const backing = new Map<string, EnrichmentReport>();
    const operations: string[] = [];
    const external: EnrichmentCache = {
      async get(key) {
        operations.push("get");
        await Promise.resolve();
        return backing.get(key);
      },
      async set(key, report) {
        operations.push("set");
        await Promise.resolve();
        backing.set(key, report);
      },
    };
    const legacy = new CountingEnricher("dns", "resolution");

    await inspectAsync(BENIGN, { cache: external, enrichers: [legacy] });
    const cached = await inspectAsync(BENIGN, { cache: external, enrichers: [legacy] });

    expect(operations).toEqual(["get", "set", "get"]);
    expect(legacy.calls).toBe(1);
    expect([...backing.values()][0]).toMatchObject({
      schemaVersion: ENRICHMENT_SCHEMA_VERSION,
      outcomes: [{ sourceId: "dns", layer: "resolution", status: "success" }],
    });
    expect(cached.reasons.some((reason) => reason.code === "ip_private")).toBe(true);
  });
});

describe("enrichment cache — dynamic positive and negative lifetimes (K9)", () => {
  it("passes response-derived TTLs to the store for positive and no-hit reports", async () => {
    const writes: Array<{ key: string; ttlMs: number; status: string }> = [];
    const cache: EnrichmentCache = {
      get: () => undefined,
      set(key, value, ttlMs) {
        writes.push({ key, ttlMs, status: value.outcomes[0]!.status });
      },
    };
    const positive: Enricher = {
      id: "positive.fixture",
      layer: "resolution",
      cacheKey: () => "example.com",
      cacheTtlMsFor: (value) =>
        value.outcomes.every((outcome) => outcome.status === "no-hit") ? 25 : 250,
      async enrich() {
        return structuredReport("positive.fixture", "resolution");
      },
    };
    const negative: Enricher = {
      id: "negative.fixture",
      layer: "reputation",
      cacheKey: () => "example.com",
      cacheTtlMsFor: (value) =>
        value.outcomes.every((outcome) => outcome.status === "no-hit") ? 25 : 250,
      async enrich() {
        return structuredReport("negative.fixture", "reputation", []);
      },
    };

    await inspectAsync(BENIGN, { cache, enrichers: [positive, negative] });

    expect(writes.map(({ ttlMs, status }) => ({ ttlMs, status }))).toEqual([
      { ttlMs: 250, status: "success" },
      { ttlMs: 25, status: "no-hit" },
    ]);
    expect(writes[0]!.key).not.toBe(writes[1]!.key);
  });

  it("negative-caches a no-hit until its provider-declared freshness expires", async () => {
    const expiresAt = Date.parse("2026-07-17T08:35:00.000Z");
    let now = expiresAt - 100;
    let calls = 0;
    const cache = new InMemoryEnrichmentCache(() => now);
    const noHitReport = structuredReport("feed.fixture", "reputation", []);
    const enricher: Enricher = {
      id: "feed.fixture",
      layer: "reputation",
      cacheKey: () => "example.com",
      cacheTtlMsFor(value) {
        const declaredExpiry = value.outcomes[0]?.freshness.expiresAt;
        return declaredExpiry === null || declaredExpiry === undefined
          ? null
          : Date.parse(declaredExpiry) - now;
      },
      async enrich() {
        calls += 1;
        return noHitReport;
      },
    };

    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    now = expiresAt - 1;
    const hit = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(calls).toBe(1);
    expect(hit.enrichment?.outcomes[0]?.status).toBe("no-hit");

    now = expiresAt;
    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });
    expect(calls).toBe(2);
  });
});

describe("enrichment cache — opaque namespace and privacy guard", () => {
  it("schema- and source-namespaces caller keys without deriving from the inspected URL", async () => {
    const keys: string[] = [];
    const cache: EnrichmentCache = {
      get(key) {
        keys.push(key);
        return undefined;
      },
      set() {},
    };
    const enricher = new CountingEnricher(
      "dns.fixture",
      "resolution",
      [PRIVATE_IP_FINDING],
      1000,
      "example.com",
    );

    await inspectAsync(BENIGN, { cache, enrichers: [enricher] });

    expect(JSON.parse(keys[0]!) as unknown).toEqual([
      `linklint:enrichment:${ENRICHMENT_SCHEMA_VERSION}`,
      "resolution:dns.fixture",
      "example.com",
    ]);
    expect(keys[0]).not.toContain(BENIGN);
  });

  it("rejects a cache key that directly discloses the full inspected URL", async () => {
    let cacheCalls = 0;
    const cache: EnrichmentCache = {
      get() {
        cacheCalls += 1;
        return undefined;
      },
      set() {
        cacheCalls += 1;
      },
    };
    const enricher = new CountingEnricher(
      "unsafe.fixture",
      "resolution",
      [PRIVATE_IP_FINDING],
      1000,
      `prefix:${BENIGN}`,
    );

    const result = await inspectAsync(BENIGN, { cache, enrichers: [enricher] });

    expect(cacheCalls).toBe(0);
    expect(enricher.calls).toBe(1);
    expect(
      result.enrichment?.outcomes.some(
        (outcome) =>
          outcome.status === "failure" && outcome.cause.code === "cache-key-error",
      ),
    ).toBe(true);
  });
});

describe("InMemoryEnrichmentCache — unit semantics", () => {
  it("returns undefined on a miss and after expiry, the stored value within TTL", () => {
    let now = 0;
    const cache = new InMemoryEnrichmentCache(() => now);
    expect(cache.get("k")).toBeUndefined();

    const report = structuredReport("dns", "resolution");
    cache.set("k", report, 100);
    expect(cache.get("k")).toEqual(report);

    now = 100; // >= expiresAt → expired
    expect(cache.get("k")).toBeUndefined();
    // A second get confirms the expired entry was evicted (still a miss).
    expect(cache.get("k")).toBeUndefined();
  });

  it("refuses to store a non-positive or non-finite TTL", () => {
    const cache = new InMemoryEnrichmentCache(() => 0);
    const report = structuredReport("dns", "resolution");
    cache.set("a", report, 0);
    cache.set("b", report, -1);
    cache.set("c", report, Number.POSITIVE_INFINITY);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("c")).toBeUndefined();
  });
});
