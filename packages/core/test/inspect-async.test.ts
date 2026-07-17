import { describe, expect, it } from "vitest";
import { inspect, inspectAsync } from "../src/index.js";
import type {
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentLayer,
  InspectResult,
} from "../src/schema/types.js";

/**
 * Contract tests for the async enrichment framework (LINK-iprlxqxb, unit K1).
 *
 * inspectAsync = the synchronous `inspect()` (UNCHANGED, zero-network) PLUS
 * caller-supplied opt-in enrichers. These tests lock:
 *   1. no-enricher path is byte-for-byte identical to inspect();
 *   2. a configured+successful enricher adds `<layer>:<id>` to checksRun and
 *      merges its findings into reasons/confusables/score like a lexical one;
 *   3. an unconfigured layer keeps its bare placeholder in checksSkipped;
 *   4. a throwing/rejecting enricher degrades to checksSkipped, never crashes;
 *   5. the AbortSignal is threaded through; an aborted signal degrades to a skip.
 *
 * All enrichers here are NO-NETWORK test doubles: they return canned findings.
 */

const BENIGN = "https://www.example.com/path";

/**
 * A no-network test-double enricher. Returns whatever findings it is handed and
 * records the last context it saw so tests can assert signal pass-through.
 */
class FakeEnricher implements Enricher {
  lastCtx: EnrichmentContext | null = null;
  lastResult: InspectResult | null = null;
  calls = 0;

  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    private readonly findings: EnricherFinding[] = [],
  ) {}

  async enrich(result: InspectResult, ctx: EnrichmentContext): Promise<EnricherFinding[]> {
    this.calls += 1;
    this.lastCtx = ctx;
    this.lastResult = result;
    return this.findings;
  }
}

/** A test double that always rejects — exercises graceful degradation. */
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

/** A resolution finding that resolves to a private IP (a plausible L2 signal). */
const PRIVATE_IP_FINDING: EnricherFinding = {
  code: "ip_private",
  detail: "resolved host maps to a private/internal IP",
};

describe("inspectAsync — no-enricher path is byte-identical to inspect() (HARD invariant)", () => {
  const urls = [BENIGN, "https://paypal.com@evil.ru/", "javascript:alert(1)", "ht!tp://%%%not a url"];

  it.each(urls)("inspectAsync(%s) deep-equals inspect(%s)", async (url) => {
    expect(await inspectAsync(url)).toEqual(inspect(url));
  });

  it.each(urls)("inspectAsync(%s, { enrichers: [] }) deep-equals inspect(%s)", async (url) => {
    expect(await inspectAsync(url, { enrichers: [] })).toEqual(inspect(url));
  });

  it("passes InspectOptions through to the sync pass unchanged", async () => {
    const opts = { agentMode: true as const };
    expect(await inspectAsync(BENIGN, opts)).toEqual(inspect(BENIGN, opts));
  });
});

describe("inspectAsync — a configured+successful enricher is observable", () => {
  it("adds `<layer>:<id>` to checksRun and drops the bare layer placeholder", async () => {
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });

    expect(r.checksRun).toContain("resolution:dns");
    expect(r.checksRun).toContain("lexical");
    // The configured layer's bare placeholder is gone; the unconfigured one stays.
    expect(r.checksSkipped).not.toContain("resolution");
    expect(r.checksSkipped).toContain("reputation");
  });

  it("merges findings into reasons and scoring the same way lexical findings do", async () => {
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });

    const reason = r.reasons.find((x) => x.code === "ip_private");
    expect(reason).toBeDefined();
    // layer + weight come from the reason-code registry, identical to a lexical
    // finding that emits the same code.
    expect(reason?.layer).toBe("lexical");
    expect(reason?.weight).toBe(0.2);

    // The base URL scored 0; the enrichment finding moves the score exactly as
    // aggregate() would for a lexical finding of the same weight.
    expect(inspect(BENIGN).score).toBe(0);
    expect(r.score).toBeCloseTo(0.2, 10);
    expect(r.severity).toBe("low");
  });

  it("bubbles enricher confusables up to top-level confusables[]", async () => {
    const finding: EnricherFinding = {
      code: "confusable_char",
      detail: "resolved label carries a confusable",
      confusables: [
        {
          char: "а",
          codepoint: "U+0430",
          confusableWith: "a (U+0061)",
          component: "host",
          position: 0,
        },
      ],
    };
    const enricher = new FakeEnricher("dns", "resolution", [finding]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });
    expect(r.confusables).toHaveLength(1);
    expect(r.confusables[0]?.codepoint).toBe("U+0430");
  });
});

describe("inspectAsync — unconfigured layers stay skipped (never silently clean)", () => {
  it("keeps the reputation placeholder when only a resolution enricher runs", async () => {
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });
    expect(r.checksSkipped).toContain("reputation");
    expect(r.checksSkipped).not.toContain("resolution");
  });

  it("with no enrichers, both layers remain bare-skipped", async () => {
    const r = await inspectAsync(BENIGN, { enrichers: [] });
    expect(r.checksSkipped).toEqual(["resolution", "reputation"]);
    expect(r.checksRun).toEqual(["lexical"]);
  });
});

describe("inspectAsync — graceful degradation (load-bearing)", () => {
  it("a throwing enricher degrades to checksSkipped without crashing the call", async () => {
    const bad = new ThrowingEnricher("flaky", "reputation");
    const r = await inspectAsync(BENIGN, { enrichers: [bad] });

    expect(bad.calls).toBe(1);
    expect(r.status).toBe("ok");
    expect(r.checksSkipped).toContain("reputation:flaky");
    // A failed enricher must NOT appear in checksRun and must add no reasons.
    expect(r.checksRun).not.toContain("reputation:flaky");
    expect(r.reasons).toEqual(inspect(BENIGN).reasons);
  });

  it("one enricher failing does not stop the others in the same layer", async () => {
    const good = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const bad = new ThrowingEnricher("rdap", "resolution");
    const r = await inspectAsync(BENIGN, { enrichers: [good, bad] });

    expect(r.checksRun).toContain("resolution:dns");
    expect(r.checksSkipped).toContain("resolution:rdap");
    // The configured layer's bare placeholder is dropped even though one failed.
    expect(r.checksSkipped).not.toContain("resolution");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(true);
  });
});

describe("inspectAsync — confidence aggregation (FR-SCORE-2b)", () => {
  it("lexical-only (no enrichers) stays fully confident at 1.0", async () => {
    const r = await inspectAsync(BENIGN, { enrichers: [] });
    expect(r.confidence).toBe(1);
    // And the no-enricher path remains deep-equal to sync inspect().
    expect(r).toEqual(inspect(BENIGN));
  });

  it("a finding with confidence 0.6 drives the result confidence to 0.6", async () => {
    const finding: EnricherFinding = { ...PRIVATE_IP_FINDING, confidence: 0.6 };
    const enricher = new FakeEnricher("dns", "resolution", [finding]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });
    expect(r.confidence).toBeCloseTo(0.6, 10);
    // confidence is independent of score: the score still moves by the weight.
    expect(r.score).toBeCloseTo(0.2, 10);
  });

  it("a finding that omits confidence contributes 1.0 (leaves it unchanged)", async () => {
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher] });
    expect(r.confidence).toBe(1);
  });

  it("takes the MINIMUM confidence across multiple contributing findings", async () => {
    const low: EnricherFinding = { ...PRIVATE_IP_FINDING, confidence: 0.4 };
    const mid: EnricherFinding = {
      code: "risky_tld",
      detail: "reputation signal",
      confidence: 0.7,
    };
    const dns = new FakeEnricher("dns", "resolution", [low]);
    const rep = new FakeEnricher("rep", "reputation", [mid]);
    const r = await inspectAsync(BENIGN, { enrichers: [dns, rep] });
    expect(r.confidence).toBeCloseTo(0.4, 10);
  });

  it("a skipped/failed enricher contributes nothing to confidence", async () => {
    const bad = new ThrowingEnricher("flaky", "reputation");
    const r = await inspectAsync(BENIGN, { enrichers: [bad] });
    // Failure is visible in checksSkipped, not in confidence, which stays 1.0.
    expect(r.checksSkipped).toContain("reputation:flaky");
    expect(r.confidence).toBe(1);
  });
});

describe("inspectAsync — AbortSignal threading", () => {
  it("threads a signal that follows the caller's signal into the enricher context", async () => {
    const controller = new AbortController();
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    await inspectAsync(BENIGN, { enrichers: [enricher], signal: controller.signal });
    expect(enricher.lastCtx?.signal).toBeDefined();
    expect(enricher.lastCtx?.signal?.aborted).toBe(false);
    controller.abort();
    expect(enricher.lastCtx?.signal?.aborted).toBe(true);
  });

  it("an already-aborted signal degrades every enricher to a skip (not invoked)", async () => {
    const controller = new AbortController();
    controller.abort();
    const enricher = new FakeEnricher("dns", "resolution", [PRIVATE_IP_FINDING]);
    const r = await inspectAsync(BENIGN, { enrichers: [enricher], signal: controller.signal });

    expect(enricher.calls).toBe(0);
    expect(r.checksSkipped).toContain("resolution:dns");
    expect(r.checksRun).not.toContain("resolution:dns");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(false);
  });

  it("a signal-aware enricher that rejects on abort degrades to a skip", async () => {
    const controller = new AbortController();
    const enricher: Enricher = {
      id: "dns",
      layer: "resolution",
      async enrich(_result, ctx) {
        controller.abort();
        if (ctx.signal?.aborted) throw new Error("aborted");
        return [PRIVATE_IP_FINDING];
      },
    };
    const r = await inspectAsync(BENIGN, { enrichers: [enricher], signal: controller.signal });
    expect(r.checksSkipped).toContain("resolution:dns");
    expect(r.reasons.some((x) => x.code === "ip_private")).toBe(false);
  });
});
