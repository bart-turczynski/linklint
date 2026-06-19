import { describe, expect, it } from "vitest";
import { aggregate } from "../src/scoring/score.js";
import { severityForScore } from "../src/scoring/weights.js";
import type { Reason } from "../src/schema/types.js";

function reason(weight: number): Reason {
  return { code: "x", layer: "lexical", detail: "", weight };
}

describe("aggregate (probabilistic OR)", () => {
  it("is 0 with no scoring reasons", () => {
    expect(aggregate([]).score).toBe(0);
    expect(aggregate([reason(0), reason(0)]).score).toBe(0);
  });

  it("matches the PRD worked example: 0.5 + 0.4 -> 0.7", () => {
    const { score, severity } = aggregate([reason(0.5), reason(0.4)]);
    expect(score).toBeCloseTo(0.7, 10);
    expect(severity).toBe("high");
  });

  it("is order-independent", () => {
    const a = aggregate([reason(0.5), reason(0.4), reason(0.15)]).score;
    const b = aggregate([reason(0.15), reason(0.4), reason(0.5)]).score;
    expect(a).toBeCloseTo(b, 12);
  });

  it("never exceeds 1 as signals stack", () => {
    const { score } = aggregate([reason(0.9), reason(0.9), reason(0.9), reason(0.9)]);
    expect(score).toBeGreaterThan(0.99);
    expect(score).toBeLessThanOrEqual(1);
  });

  it("ignores weight-0 informational reasons", () => {
    expect(aggregate([reason(0.4), reason(0)]).score).toBeCloseTo(0.4, 12);
  });
});

describe("severityForScore bands (FR-SCORE-1b)", () => {
  it("maps band boundaries correctly", () => {
    expect(severityForScore(0)).toBe("info");
    expect(severityForScore(0.0001)).toBe("low");
    expect(severityForScore(0.25)).toBe("low");
    expect(severityForScore(0.2501)).toBe("medium");
    expect(severityForScore(0.5)).toBe("medium");
    expect(severityForScore(0.5001)).toBe("high");
    expect(severityForScore(0.8)).toBe("high");
    expect(severityForScore(0.8001)).toBe("critical");
    expect(severityForScore(1)).toBe("critical");
  });
});
