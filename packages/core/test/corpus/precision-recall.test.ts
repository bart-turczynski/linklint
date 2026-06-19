import { describe, expect, it } from "vitest";
import { runHarness } from "./harness.js";

// D2 — precision/recall harness over the labeled corpus.
describe("precision / recall harness", () => {
  const summary = runHarness();

  it("reports the corpus P/R summary", () => {
    // Visible in test output for tracking as detectors evolve.
    console.log(
      `[corpus] n=${summary.total} TP=${summary.truePositives} FN=${summary.falseNegatives} ` +
        `FP=${summary.falsePositives} TN=${summary.trueNegatives} ` +
        `precision=${summary.precision.toFixed(3)} recall=${summary.recall.toFixed(3)}`,
    );
    expect(summary.total).toBeGreaterThan(0);
  });

  it("has ZERO false positives on the benign/info set (SC-2)", () => {
    expect(summary.falsePositives, `false positives: ${summary.falsePositiveInputs.join(", ")}`).toBe(
      0,
    );
  });

  it("flags every deceptive row (recall = 1 on the corpus)", () => {
    expect(summary.falseNegatives, `missed: ${summary.falseNegativeInputs.join(", ")}`).toBe(0);
    expect(summary.recall).toBe(1);
  });

  it("precision is 1 on the corpus", () => {
    expect(summary.precision).toBe(1);
  });
});
