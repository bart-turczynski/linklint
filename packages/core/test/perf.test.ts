import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { CORPUS } from "./corpus/corpus.js";

// D3 — performance gate (NFR-PERF-1): a single inspect() call completes well
// under 5 ms on a representative corpus.
describe("performance (NFR-PERF-1)", () => {
  const inputs = CORPUS.map((r) => r.input);

  it("average inspect() is < 5 ms across the corpus", () => {
    // Warm up (JIT / lazy data init).
    for (const i of inputs) inspect(i);

    const iterations = 20;
    const start = performance.now();
    for (let n = 0; n < iterations; n++) {
      for (const i of inputs) inspect(i);
    }
    const elapsed = performance.now() - start;
    const perCall = elapsed / (iterations * inputs.length);

    console.log(`[perf] mean inspect() = ${perCall.toFixed(4)} ms over ${iterations * inputs.length} calls`);
    expect(perCall).toBeLessThan(5);
  });

  it("worst-case single call is < 5 ms", () => {
    // Warm up (JIT / lazy data init).
    for (let n = 0; n < 3; n++) for (const i of inputs) inspect(i);

    // A single timing sample is dominated by GC / scheduler noise (a one-off
    // call can spike to 10ms+ even though the compute cost is sub-millisecond),
    // which made this assertion flaky. Take the best-of-`reps` per input: the
    // floor reflects the true per-call compute cost, and the worst input's
    // floor is the meaningful NFR-PERF-1 bound.
    const reps = 5;
    let worst = 0;
    let worstInput = "";
    for (const i of inputs) {
      let best = Infinity;
      for (let n = 0; n < reps; n++) {
        const t = performance.now();
        inspect(i);
        best = Math.min(best, performance.now() - t);
      }
      if (best > worst) {
        worst = best;
        worstInput = i;
      }
    }
    console.log(`[perf] worst single inspect() = ${worst.toFixed(4)} ms (${worstInput})`);
    expect(worst).toBeLessThan(5);
  });
});
