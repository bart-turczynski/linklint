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
    for (const i of inputs) inspect(i); // warm up
    let worst = 0;
    for (const i of inputs) {
      const t = performance.now();
      inspect(i);
      worst = Math.max(worst, performance.now() - t);
    }
    console.log(`[perf] worst single inspect() = ${worst.toFixed(4)} ms`);
    expect(worst).toBeLessThan(5);
  });
});
