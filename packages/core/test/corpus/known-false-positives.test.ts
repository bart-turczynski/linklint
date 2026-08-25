import { describe, expect, it } from "vitest";
import { inspect } from "../../src/index.js";
import { CORPUS } from "./corpus.js";
import { EMBARRASSMENT_CORPUS, KNOWN_AND_ACCEPTED } from "./embarrassment.js";
import { KNOWN_FALSE_POSITIVES } from "./known-false-positives.js";

// LINK-tsvngawn — see known-false-positives.ts for why this register exists and
// why its one assertion is inverted.

function scoreOf(input: string): number {
  const result = inspect(input);
  expect(result.status, `${input}: expected a parseable URL`).toBe("ok");
  return result.score ?? 0;
}

describe("known false positives", () => {
  // Guarded because an EMPTY register is the good state, and vitest fails a
  // suite that declares no tests. The empty case is covered by hygiene below.
  if (KNOWN_FALSE_POSITIVES.length > 0) {
    describe("each entry states the verdict we want, and does not get it yet", () => {
      // `it.fails` inverts the result: these go RED the moment the string stops
      // scoring, which is the signal to promote the entry to a benign corpus row
      // in corpus.ts and delete it from here.
      it.fails.each(KNOWN_FALSE_POSITIVES.map((e) => [e.input, e] as const))(
        "%s (known FP)",
        (_name, entry) => {
          expect(
            scoreOf(entry.input),
            `${entry.input} is now quiet — the exposure tracked by ${entry.issue} is closed. ` +
              "Move it to corpus.ts as a benign row and remove it from this register.",
          ).toBe(0);
        },
      );
    });
  }

  describe("register hygiene", () => {
    it("has no duplicate entries", () => {
      const inputs = KNOWN_FALSE_POSITIVES.map((e) => e.input);
      expect(inputs.length).toBe(new Set(inputs).size);
    });

    it("gives every entry a rationale and an observed verdict", () => {
      for (const entry of KNOWN_FALSE_POSITIVES) {
        expect(entry.why.trim().length, `${entry.input}: empty rationale`).toBeGreaterThan(0);
        expect(entry.observed.trim().length, `${entry.input}: no observed verdict`).toBeGreaterThan(
          0,
        );
      }
    });

    it("points every entry at a tracked issue", () => {
      for (const entry of KNOWN_FALSE_POSITIVES) {
        expect(entry.issue, `${entry.input}: malformed issue id`).toMatch(/^LINK-[a-z]+$/);
      }
    });

    it("never files the same string as both a known FP and a passing corpus row", () => {
      // The contradiction this register exists to avoid: a `benign` corpus row
      // asserts score 0 and would simply be red, and a `deceptive` row would
      // assert the overreach is correct.
      const corpusInputs = new Set(CORPUS.map((r) => r.input));
      for (const entry of KNOWN_FALSE_POSITIVES) {
        expect(corpusInputs.has(entry.input), `${entry.input} is both a corpus row and a known FP`).toBe(
          false,
        );
      }
    });

    it("keeps the two registers in separate directions", () => {
      // embarrassment.ts holds MISSES (should score, does not) and its
      // KNOWN_AND_ACCEPTED holds accepted zero scores. This register holds
      // OVERREACH (should not score, does). No string belongs to both.
      const other = new Set([...EMBARRASSMENT_CORPUS.map((e) => e.input), ...KNOWN_AND_ACCEPTED]);
      for (const entry of KNOWN_FALSE_POSITIVES) {
        expect(
          other.has(entry.input),
          `${entry.input} is filed as both a miss and an overreach`,
        ).toBe(false);
      }
    });
  });
});
