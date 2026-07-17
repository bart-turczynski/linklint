import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_ENRICHMENT_TIMEOUT_MS,
  InMemoryEnrichmentGovernor,
  inspect,
  inspectAsync,
  type Enricher,
  type EnricherFinding,
  type EnrichmentCache,
  type EnrichmentGovernor,
  type InspectResult,
} from "../src/index.js";

/** K8 bounded-execution and total-boundary fixtures. No fixture performs I/O. */

const URL = "https://www.example.com/path";
const FINDING: EnricherFinding = {
  code: "ip_private",
  detail: "deterministic fixture finding",
};

function outcomeCauses(result: InspectResult): string[] {
  return (
    result.enrichment?.outcomes.flatMap((outcome) =>
      outcome.status === "skipped" || outcome.status === "failure"
        ? [outcome.cause.code]
        : [],
    ) ?? []
  );
}

afterEach(() => {
  vi.useRealTimers();
});

describe("K8 — every configured source is runner-bounded by default", () => {
  it("hard-bounds a never-settling source without caller governor setup", async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    const enricher: Enricher = {
      id: "never",
      layer: "resolution",
      enrich(_result, context) {
        signal = context.signal;
        return new Promise(() => {});
      },
    };

    const pending = inspectAsync(URL, { enrichers: [enricher] });
    await vi.advanceTimersByTimeAsync(DEFAULT_ENRICHMENT_TIMEOUT_MS - 1);
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    const result = await pending;
    expect(signal?.aborted).toBe(true);
    expect(outcomeCauses(result)).toContain("timeout");
    expect(result.checksSkipped).toContain("resolution:never");
  });

  it("honors a positive per-source override without a governor", async () => {
    vi.useFakeTimers();
    const enricher: Enricher = {
      id: "short-budget",
      layer: "resolution",
      timeoutMs: 25,
      enrich: () => new Promise(() => {}),
    };

    const pending = inspectAsync(URL, { enrichers: [enricher] });
    await vi.advanceTimersByTimeAsync(25);
    expect(outcomeCauses(await pending)).toContain("timeout");
  });

  it("uses null as the explicit opt-out while invalid numeric values retain the safe default", async () => {
    vi.useFakeTimers();
    const unbounded: Enricher = {
      id: "externally-bounded",
      layer: "resolution",
      timeoutMs: null,
      enrich: () => new Promise(() => {}),
    };
    let unboundedSettled = false;
    void inspectAsync(URL, { enrichers: [unbounded] }).then(() => {
      unboundedSettled = true;
    });
    await vi.advanceTimersByTimeAsync(DEFAULT_ENRICHMENT_TIMEOUT_MS * 2);
    expect(unboundedSettled).toBe(false);

    const invalidNumeric: Enricher = {
      id: "invalid-zero",
      layer: "reputation",
      timeoutMs: 0,
      enrich: () => new Promise(() => {}),
    };
    const pending = inspectAsync(URL, { enrichers: [invalidNumeric] });
    await vi.advanceTimersByTimeAsync(DEFAULT_ENRICHMENT_TIMEOUT_MS);
    expect(outcomeCauses(await pending)).toContain("timeout");
  });

  it("still leaves sync and no-enricher async output byte-identical", async () => {
    expect(await inspectAsync(URL)).toEqual(inspect(URL));
    expect(await inspectAsync(URL, { enrichers: [] })).toEqual(inspect(URL));
  });
});

describe("K8 — degradation causes are machine-distinguishable", () => {
  it("distinguishes rate limiting from an active backoff window", async () => {
    let now = 0;
    const rateGovernor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 1,
      refillIntervalMs: Number.POSITIVE_INFINITY,
    });
    const successful: Enricher = {
      id: "rate",
      layer: "resolution",
      async enrich() {
        return [FINDING];
      },
    };
    await inspectAsync(URL, { governor: rateGovernor, enrichers: [successful] });
    const rateLimited = await inspectAsync(URL, {
      governor: rateGovernor,
      enrichers: [successful],
    });
    expect(outcomeCauses(rateLimited)).toEqual(["rate-limited"]);

    const backoffGovernor = new InMemoryEnrichmentGovernor({
      now: () => now,
      capacity: 10,
      backoffBaseMs: 1000,
    });
    const failing: Enricher = {
      id: "backoff",
      layer: "reputation",
      async enrich() {
        throw new Error("fixture provider failure");
      },
    };
    const failed = await inspectAsync(URL, {
      governor: backoffGovernor,
      enrichers: [failing],
    });
    expect(outcomeCauses(failed)).toContain("source-error");

    now = 1;
    const backedOff = await inspectAsync(URL, {
      governor: backoffGovernor,
      enrichers: [failing],
    });
    expect(outcomeCauses(backedOff)).toEqual(["backoff-active"]);
  });

  it("keeps caller abort, timeout, malformed output, and provider failure distinct", async () => {
    const controller = new AbortController();
    controller.abort();
    const neverCalled: Enricher = {
      id: "aborted",
      layer: "resolution",
      async enrich() {
        return [FINDING];
      },
    };
    expect(
      outcomeCauses(
        await inspectAsync(URL, {
          signal: controller.signal,
          enrichers: [neverCalled],
        }),
      ),
    ).toEqual(["caller-aborted"]);

    const malformed: Enricher = {
      id: "malformed",
      layer: "resolution",
      async enrich() {
        return { not: "an enrichment report" } as never;
      },
    };
    expect(outcomeCauses(await inspectAsync(URL, { enrichers: [malformed] }))).toEqual([
      "invalid-output",
    ]);

    const failed: Enricher = {
      id: "failed",
      layer: "reputation",
      async enrich() {
        throw new Error("provider failed");
      },
    };
    expect(outcomeCauses(await inspectAsync(URL, { enrichers: [failed] }))).toEqual([
      "source-error",
    ]);
  });
});

describe("K8 — cache boundaries are total and visible", () => {
  it("guards a throwing cache key and still runs the source uncached", async () => {
    let calls = 0;
    const enricher: Enricher = {
      id: "key",
      layer: "resolution",
      cacheTtlMs: 1000,
      cacheKey() {
        throw new Error("key failure");
      },
      async enrich() {
        calls += 1;
        return [FINDING];
      },
    };

    const result = await inspectAsync(URL, {
      cache: { get: () => undefined, set: () => {} },
      enrichers: [enricher],
    });
    expect(calls).toBe(1);
    expect(outcomeCauses(result)).toContain("cache-key-error");
    expect(result.checksRun).toContain("resolution:key");
    expect(result.checksSkipped).toContain("resolution:key");
  });

  it("guards cache reads and writes without rejecting or discarding provider evidence", async () => {
    const readFailure: EnrichmentCache = {
      get() {
        throw new Error("read failure");
      },
      set() {},
    };
    const writeFailure: EnrichmentCache = {
      get: () => undefined,
      set() {
        throw new Error("write failure");
      },
    };
    const enricher: Enricher = {
      id: "cache",
      layer: "resolution",
      cacheTtlMs: 1000,
      cacheKey: () => "fixture-host",
      async enrich() {
        return [FINDING];
      },
    };

    const readResult = await inspectAsync(URL, {
      cache: readFailure,
      enrichers: [enricher],
    });
    expect(outcomeCauses(readResult)).toContain("cache-read-error");
    expect(readResult.reasons.some((reason) => reason.code === "ip_private")).toBe(true);

    const writeResult = await inspectAsync(URL, {
      cache: writeFailure,
      enrichers: [enricher],
    });
    expect(outcomeCauses(writeResult)).toContain("cache-write-error");
    expect(writeResult.reasons.some((reason) => reason.code === "ip_private")).toBe(true);
  });
});

describe("K8 — governor boundaries are total and per-source isolated", () => {
  it("fails one source closed when governor admission throws while a sibling completes", async () => {
    let blockedCalls = 0;
    const governor: EnrichmentGovernor = {
      admit(token) {
        if (token === "resolution:blocked") throw new Error("admission failure");
        return { run: true };
      },
      recordSuccess() {},
      recordFailure() {},
    };
    const blocked: Enricher = {
      id: "blocked",
      layer: "resolution",
      async enrich() {
        blockedCalls += 1;
        return [FINDING];
      },
    };
    const good: Enricher = {
      id: "good",
      layer: "reputation",
      async enrich() {
        return [{ code: "risky_tld", detail: "fixture reputation finding" }];
      },
    };

    const result = await inspectAsync(URL, { governor, enrichers: [blocked, good] });
    expect(blockedCalls).toBe(0);
    expect(outcomeCauses(result)).toContain("governor-error");
    expect(result.checksSkipped).toContain("resolution:blocked");
    expect(result.checksRun).toContain("reputation:good");
  });

  it("guards governor lifecycle exceptions after both success and failure", async () => {
    const brokenSuccess: EnrichmentGovernor = {
      admit: () => ({ run: true }),
      recordSuccess() {
        throw new Error("state write failure");
      },
      recordFailure() {},
    };
    const success: Enricher = {
      id: "success",
      layer: "resolution",
      async enrich() {
        return [FINDING];
      },
    };
    const successResult = await inspectAsync(URL, {
      governor: brokenSuccess,
      enrichers: [success],
    });
    expect(outcomeCauses(successResult)).toContain("governor-error");
    expect(successResult.reasons.some((reason) => reason.code === "ip_private")).toBe(true);

    const brokenFailure: EnrichmentGovernor = {
      admit: () => ({ run: true }),
      recordSuccess() {},
      recordFailure() {
        throw new Error("state write failure");
      },
    };
    const failure: Enricher = {
      id: "failure",
      layer: "reputation",
      async enrich() {
        throw new Error("provider failure");
      },
    };
    const failureResult = await inspectAsync(URL, {
      governor: brokenFailure,
      enrichers: [failure],
    });
    expect(outcomeCauses(failureResult)).toEqual(
      expect.arrayContaining(["source-error", "governor-error"]),
    );
  });

  it("lets a fast sibling complete when another source times out", async () => {
    vi.useFakeTimers();
    const slow: Enricher = {
      id: "slow",
      layer: "resolution",
      timeoutMs: 20,
      enrich: () => new Promise(() => {}),
    };
    const fast: Enricher = {
      id: "fast",
      layer: "reputation",
      async enrich() {
        return [{ code: "risky_tld", detail: "fixture reputation finding" }];
      },
    };

    const pending = inspectAsync(URL, { enrichers: [slow, fast] });
    await vi.advanceTimersByTimeAsync(20);
    const result = await pending;
    expect(outcomeCauses(result)).toContain("timeout");
    expect(result.checksRun).toContain("reputation:fast");
    expect(result.checksSkipped).toContain("resolution:slow");
  });
});

describe("K8 — abandoned provider promises remain observed", () => {
  it("does not emit an unhandled rejection when a timed-out source rejects late", async () => {
    vi.useFakeTimers();
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", listener);

    try {
      let rejectLate: ((reason: unknown) => void) | undefined;
      const enricher: Enricher = {
        id: "late-rejection",
        layer: "resolution",
        timeoutMs: 10,
        enrich: () =>
          new Promise((_resolve, reject) => {
            rejectLate = reject;
          }),
      };

      const pending = inspectAsync(URL, { enrichers: [enricher] });
      await vi.advanceTimersByTimeAsync(10);
      expect(outcomeCauses(await pending)).toContain("timeout");

      rejectLate?.(new Error("late fixture rejection"));
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(0);
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", listener);
    }
  });
});
