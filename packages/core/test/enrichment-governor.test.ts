import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InMemoryEnrichmentCache,
  InMemoryEnrichmentGovernor,
  inspect,
  inspectAsync,
  type EnrichmentCache,
  type EnrichmentGovernor,
  type GovernorDecision,
} from "../src/index.js";
import type {
  Enricher,
  EnricherFinding,
  EnrichmentLayer,
} from "../src/schema/types.js";

/**
 * Contract tests for the per-source governor (LINK-bergliii, unit K4).
 *
 * The governor is OPT-IN and pluggable, exactly like the K3 cache: nothing
 * changes unless the caller supplies one via `inspectAsync(..., { governor })`.
 * It enforces three per-source mechanisms keyed by the `<layer>:<id>` token —
 * a bounded timeout, a token-bucket rate limit, and exponential backoff — so
 * that one slow or failing source can NEVER block the verdict.
 *
 * These tests lock:
 *   1. no-governor path behaves exactly as K1–K3;
 *   2. cache-BEFORE-governor: a HIT never consults the governor (no token, no
 *      timeout, no backoff);
 *   3. rate limit: an out-of-tokens source is SKIPPED (never blocked), refilling
 *      over time (deterministic injected clock — no sleeps);
 *   4. backoff: after a failure the source is skipped WITHOUT calling enrich until
 *      the window elapses; the window grows exponentially and resets on success;
 *   5. bounded timeout: a never-resolving enrich degrades to checksSkipped, its
 *      signal aborts, and it records a failure (driven by fake timers — no real
 *      wall-clock sleeps);
 *   6. token-consume timing + governor lifecycle (admit/recordSuccess/recordFailure);
 *   7. InMemoryEnrichmentGovernor unit semantics.
 */

const BENIGN = "https://www.example.com/path";

const PRIVATE_IP_FINDING: EnricherFinding = {
  code: "ip_private",
  detail: "resolved host maps to a private/internal IP",
};

/** A counting no-network enricher; records how many times `enrich` actually ran. */
class CountingEnricher implements Enricher {
  calls = 0;
  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    private readonly findings: EnricherFinding[] = [PRIVATE_IP_FINDING],
    readonly cacheTtlMs: number = 1000,
    private readonly key: string | null = null,
  ) {}
  cacheKey(): string | null {
    return this.key;
  }
  async enrich(): Promise<EnricherFinding[]> {
    this.calls += 1;
    return this.findings;
  }
}

/** Always rejects — exercises backoff / failure recording. */
class ThrowingEnricher implements Enricher {
  calls = 0;
  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
  ) {}
  async enrich(): Promise<EnricherFinding[]> {
    this.calls += 1;
    throw new Error("boom");
  }
}

/**
 * A pluggable governor test double that records every call and returns a fixed
 * decision. Lets tests assert the runner's ordering + lifecycle wiring without the
 * in-memory policy math.
 */
class RecordingGovernor implements EnrichmentGovernor {
  admits: string[] = [];
  successes: string[] = [];
  failures: string[] = [];
  constructor(private readonly decision: GovernorDecision = { run: true }) {}
  admit(token: string): GovernorDecision {
    this.admits.push(token);
    return this.decision;
  }
  recordSuccess(token: string): void {
    this.successes.push(token);
  }
  recordFailure(token: string): void {
    this.failures.push(token);
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("governor — no-governor path is unchanged (K1–K3 preserved)", () => {
  it("supplying a governor but no enrichers leaves the result byte-identical", async () => {
    const governor = new InMemoryEnrichmentGovernor();
    expect(await inspectAsync(BENIGN, { governor, enrichers: [] })).toEqual(inspect(BENIGN));
  });

  it("an enricher's timeoutMs is inert without a governor (never bounds the call)", async () => {
    vi.useFakeTimers();
    const enricher: Enricher = {
      id: "slow",
      layer: "resolution",
      timeoutMs: 50,
      enrich: () => new Promise<EnricherFinding[]>(() => {}), // never resolves
    };
    let settled = false;
    // No governor → no timeout machinery, so this never settles even long past 50ms.
    void inspectAsync(BENIGN, { enrichers: [enricher] }).then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(settled).toBe(false);
  });
});

describe("governor — cache is consulted BEFORE the governor", () => {
  it("a cache HIT never touches the governor (no admit, no token, no backoff)", async () => {
    // A pre-populated custom cache always hits; a governor that would DENY every
    // admit. The hit must still serve findings, proving cache-before-governor.
    const backing: EnricherFinding[] = [PRIVATE_IP_FINDING];
    const cache: EnrichmentCache = {
      get: () => backing,
      set: () => {},
    };
    const governor = new RecordingGovernor({ run: false });
    const enricher = new CountingEnricher("dns", "resolution", backing, 1000, "example.com");

    const r = await inspectAsync(BENIGN, { cache, governor, enrichers: [enricher] });

    expect(enricher.calls).toBe(0); // served from cache, never ran
    expect(governor.admits).toEqual([]); // governor never consulted on a hit
    expect(r.checksRun).toContain("resolution:dns");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(true);
  });

  it("a cache MISS consults the governor; a denial skips without calling enrich", async () => {
    const governor = new RecordingGovernor({ run: false });
    const enricher = new CountingEnricher("dns", "resolution");
    const r = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });

    expect(governor.admits).toEqual(["resolution:dns"]);
    expect(enricher.calls).toBe(0); // denied → never invoked
    expect(r.checksSkipped).toContain("resolution:dns");
    expect(r.checksRun).not.toContain("resolution:dns");
  });
});

describe("governor — lifecycle wiring (admit / recordSuccess / recordFailure)", () => {
  it("an admitted success records a success (and no failure)", async () => {
    const governor = new RecordingGovernor({ run: true });
    const enricher = new CountingEnricher("dns", "resolution");
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(governor.successes).toEqual(["resolution:dns"]);
    expect(governor.failures).toEqual([]);
  });

  it("an admitted throw records a failure (and no success)", async () => {
    const governor = new RecordingGovernor({ run: true });
    const enricher = new ThrowingEnricher("flaky", "reputation");
    const r = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(governor.failures).toEqual(["reputation:flaky"]);
    expect(governor.successes).toEqual([]);
    expect(r.checksSkipped).toContain("reputation:flaky");
  });
});

describe("governor — token-bucket rate limit (skip, never block)", () => {
  it("skips an out-of-tokens source, refilling over time (deterministic clock)", async () => {
    let now = 0;
    const governor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 1,
      refillIntervalMs: 1000,
    });
    const enricher = new CountingEnricher("dns", "resolution");

    // First call spends the only token → runs.
    const first = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(first.checksRun).toContain("resolution:dns");

    // Second call at the same instant: bucket empty → SKIP (not blocked).
    const second = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(second.checksSkipped).toContain("resolution:dns");
    expect(second.checksRun).not.toContain("resolution:dns");

    // After one refill interval a token is back → runs again.
    now = 1000;
    const third = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);
    expect(third.checksRun).toContain("resolution:dns");
  });
});

describe("governor — exponential backoff (skip without calling enrich)", () => {
  it("opens a window on failure, skips within it, re-attempts after it, and grows", async () => {
    let now = 0;
    const governor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 100, // large so backoff, not rate limit, is what's under test
      backoffBaseMs: 1000,
    });
    const enricher = new ThrowingEnricher("flaky", "reputation");

    // Failure #1 → window [0, 1000).
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);

    // Within the window: skipped WITHOUT invoking enrich.
    now = 500;
    const skipped = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(skipped.checksSkipped).toContain("reputation:flaky");

    // At the window edge: re-attempted → fails again → window doubles to 2000.
    now = 1000;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);

    // 1500 is inside [1000, 3000) → still skipped (exponential growth).
    now = 1500;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(2);

    // 3000 clears the doubled window → re-attempt.
    now = 3000;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(3);
  });

  it("a success resets the backoff schedule", async () => {
    let now = 0;
    const governor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 100,
      backoffBaseMs: 1000,
    });
    let shouldThrow = true;
    const enricher: Enricher & { calls: number } = {
      id: "dns",
      layer: "resolution",
      calls: 0,
      async enrich() {
        this.calls += 1;
        if (shouldThrow) throw new Error("transient");
        return [PRIVATE_IP_FINDING];
      },
    };

    await inspectAsync(BENIGN, { governor, enrichers: [enricher] }); // fail → window 1000
    now = 1000;
    shouldThrow = false;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] }); // succeed → reset
    now = 1000;
    shouldThrow = true;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] }); // fail → window base again
    expect(enricher.calls).toBe(3);

    // Post-reset the window is base (1000), not the doubled 2000: at 2000 it clears.
    now = 2000;
    await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(4);
  });
});

describe("governor — bounded timeout (a slow source can never block the verdict)", () => {
  it("a never-resolving enrich degrades to checksSkipped on timeout, aborting its signal", async () => {
    vi.useFakeTimers();
    const governor = new InMemoryEnrichmentGovernor({ defaultTimeoutMs: 5000 });
    let seen: AbortSignal | undefined;
    const enricher: Enricher = {
      id: "slow",
      layer: "resolution",
      enrich(_result, ctx) {
        seen = ctx.signal;
        return new Promise<EnricherFinding[]>(() => {}); // never resolves
      },
    };

    const pending = inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    await vi.advanceTimersByTimeAsync(5000);
    const r = await pending;

    expect(r.status).toBe("ok");
    expect(r.checksSkipped).toContain("resolution:slow");
    expect(r.checksRun).not.toContain("resolution:slow");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(false);
    expect(seen?.aborted).toBe(true); // the composed signal fired
  });

  it("an enricher's timeoutMs overrides the governor default", async () => {
    vi.useFakeTimers();
    const governor = new RecordingGovernor({ run: true, timeoutMs: 5000 });
    const enricher: Enricher = {
      id: "slow",
      layer: "resolution",
      timeoutMs: 50, // much tighter than the governor default
      enrich: () => new Promise<EnricherFinding[]>(() => {}),
    };

    const pending = inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    await vi.advanceTimersByTimeAsync(50); // only the 50ms override, not 5000
    const r = await pending;
    expect(r.checksSkipped).toContain("resolution:slow");
  });

  it("a bounded timeout records a governor failure (feeds backoff)", async () => {
    vi.useFakeTimers();
    const governor = new RecordingGovernor({ run: true, timeoutMs: 100 });
    const enricher: Enricher = {
      id: "slow",
      layer: "resolution",
      enrich: () => new Promise<EnricherFinding[]>(() => {}),
    };
    const pending = inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    await vi.advanceTimersByTimeAsync(100);
    await pending;
    expect(governor.failures).toEqual(["resolution:slow"]);
    expect(governor.successes).toEqual([]);
  });

  it("a fast enricher under a governor still runs and resets nothing (timer cleared)", async () => {
    const governor = new InMemoryEnrichmentGovernor({ defaultTimeoutMs: 5000 });
    const enricher = new CountingEnricher("dns", "resolution");
    const r = await inspectAsync(BENIGN, { governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(r.checksRun).toContain("resolution:dns");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(true);
  });
});

describe("governor — per-source independence", () => {
  it("one source's backoff does not affect another", async () => {
    let now = 0;
    const governor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 100,
      backoffBaseMs: 1000,
    });
    const bad = new ThrowingEnricher("rdap", "resolution");
    const good = new CountingEnricher("dns", "resolution");

    await inspectAsync(BENIGN, { governor, enrichers: [bad, good] });
    expect(bad.calls).toBe(1);
    expect(good.calls).toBe(1);

    // bad is now backed off; good is untouched and keeps running.
    now = 100;
    const r = await inspectAsync(BENIGN, { governor, enrichers: [bad, good] });
    expect(bad.calls).toBe(1); // still backed off
    expect(good.calls).toBe(2); // independent — ran again
    expect(r.checksSkipped).toContain("resolution:rdap");
    expect(r.checksRun).toContain("resolution:dns");
  });
});

describe("InMemoryEnrichmentGovernor — unit semantics", () => {
  it("admits a fresh source and returns the default timeout, consuming a token per admit", () => {
    let now = 0;
    const g = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 2,
      refillIntervalMs: 1000,
      defaultTimeoutMs: 4000,
    });
    expect(g.admit("resolution:x")).toEqual({ run: true, timeoutMs: 4000 });
    expect(g.admit("resolution:x")).toEqual({ run: true, timeoutMs: 4000 });
    // Capacity 2 exhausted at the same instant → denied.
    expect(g.admit("resolution:x")).toEqual({ run: false });
    // One refill interval → one token back.
    now = 1000;
    expect(g.admit("resolution:x")).toEqual({ run: true, timeoutMs: 4000 });
  });

  it("omits timeoutMs from the decision when the default is non-positive", () => {
    const g = new InMemoryEnrichmentGovernor({ defaultTimeoutMs: 0 });
    expect(g.admit("resolution:x")).toEqual({ run: true });
  });

  it("a backed-off source is denied WITHOUT spending a token", () => {
    let now = 0;
    const g = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 1,
      refillIntervalMs: 1_000_000, // effectively no refill within the test
      backoffBaseMs: 1000,
    });
    // Open a backoff window.
    g.recordFailure("resolution:x");
    // Within the window: denied, and (crucially) the lone token is NOT consumed.
    now = 500;
    expect(g.admit("resolution:x")).toEqual({ run: false });
    // Once the window clears, the still-available token admits the source.
    now = 1000;
    expect(g.admit("resolution:x")).toMatchObject({ run: true });
  });

  it("recordSuccess clears an open backoff window", () => {
    let now = 0;
    const g = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 100,
      backoffBaseMs: 1000,
    });
    g.recordFailure("resolution:x"); // window [0, 1000)
    now = 500;
    expect(g.admit("resolution:x")).toEqual({ run: false });
    g.recordSuccess("resolution:x"); // clears the window
    expect(g.admit("resolution:x")).toMatchObject({ run: true });
  });

  it("caps the backoff window at backoffMaxMs", () => {
    let now = 0;
    const g = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 100,
      backoffBaseMs: 1000,
      backoffMaxMs: 3000,
    });
    // Five consecutive failures would raw-schedule 16000ms; the cap holds it at 3000.
    for (let i = 0; i < 5; i++) g.recordFailure("resolution:x");
    now = 2999;
    expect(g.admit("resolution:x")).toEqual({ run: false });
    now = 3000;
    expect(g.admit("resolution:x")).toMatchObject({ run: true });
  });

  it("refill is capped at capacity (no unbounded token accrual)", () => {
    let now = 0;
    const g = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 2,
      refillIntervalMs: 1000,
    });
    // Idle a long time, then drain: only `capacity` admits succeed.
    now = 100_000;
    expect(g.admit("resolution:x")).toMatchObject({ run: true });
    expect(g.admit("resolution:x")).toMatchObject({ run: true });
    expect(g.admit("resolution:x")).toEqual({ run: false });
  });
});

// Interplay smoke: cache + governor together on the happy path (miss→store→hit),
// confirming a hit spends no token even when the bucket is now empty.
describe("governor × cache interplay", () => {
  it("a stored hit is served without a token even after the bucket is drained", async () => {
    let now = 0;
    const cache = new InMemoryEnrichmentCache(() => now);
    const governor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 1,
      refillIntervalMs: 1_000_000,
    });
    const enricher = new CountingEnricher(
      "dns",
      "resolution",
      [PRIVATE_IP_FINDING],
      1000,
      "example.com",
    );

    // MISS: admit spends the only token, runs, stores.
    const first = await inspectAsync(BENIGN, { cache, governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(first.checksRun).toContain("resolution:dns");

    // HIT within TTL: served from cache, no token needed (the bucket is empty).
    const second = await inspectAsync(BENIGN, { cache, governor, enrichers: [enricher] });
    expect(enricher.calls).toBe(1);
    expect(second.checksRun).toContain("resolution:dns");
    expect(second.reasons.some((x) => x.code === "ip_private")).toBe(true);
  });
});
