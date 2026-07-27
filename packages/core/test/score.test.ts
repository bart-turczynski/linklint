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

  // The raw product carries floating-point error into the PUBLIC `score` field
  // and from there into the JSON output, so it is rounded to 10dp. These are
  // exact-equality assertions on purpose: `toBeCloseTo` would pass on the
  // unrounded value and pin nothing.
  it("does not leak floating-point error into the public score", () => {
    // brand_homoglyph (0.8) + ascii_homoglyph (0.2) — computes to
    // 0.8400000000000001 without rounding.
    expect(aggregate([reason(0.8), reason(0.2)]).score).toBe(0.84);
    expect(aggregate([reason(0.65), reason(0.2)]).score).toBe(0.72);
    expect(aggregate([reason(0.5), reason(0.4)]).score).toBe(0.7);
  });

  it("keeps float error off the severity band edges", () => {
    // Exactly 0.8 is `high` — the band is (0.5, 0.8]. An ULP of accumulated
    // error above it would misread as `critical`.
    const { score, severity } = aggregate([reason(0.5), reason(0.6)]);
    expect(score).toBe(0.8);
    expect(severity).toBe("high");
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
