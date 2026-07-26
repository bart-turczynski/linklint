import { describe, expect, it } from "vitest";
import { inspect } from "../../src/index.js";
import {
  ACTIVE_ENTRIES,
  EMBARRASSMENT_CORPUS,
  KNOWN_AND_ACCEPTED,
  PENDING_ENTRIES,
} from "./embarrassment.js";

// LINK-rifmdydg — the embarrassment corpus. See embarrassment.ts for the
// rationale behind the deliberately weak assertion.

/** The one thing this corpus asserts. */
function scoreOf(input: string): number {
  const result = inspect(input);
  expect(result.status, `${input}: expected a parseable URL`).toBe("ok");
  return result.score ?? 0;
}

describe("embarrassment corpus", () => {
  describe("active guards must never score 0.00", () => {
    it.each(ACTIVE_ENTRIES.map((e) => [e.input, e] as const))("%s", (_name, entry) => {
      expect(scoreOf(entry.input), `${entry.input} scored 0.00 — ${entry.why}`).toBeGreaterThan(0);
    });
  });

  describe("pending — known misses, tracked", () => {
    // `it.fails` inverts the result: these go RED when they start passing,
    // which is the signal to promote the entry to an active guard.
    it.fails.each(PENDING_ENTRIES.map((e) => [e.input, e] as const))(
      "%s (pending)",
      (_name, entry) => {
        expect(
          scoreOf(entry.input),
          `${entry.input} now scores — remove its pendingIssue (${entry.pendingIssue}) ` +
            "and move it to the active guards.",
        ).toBeGreaterThan(0);
      },
    );
  });

  describe("corpus hygiene", () => {
    it("has no duplicate entries", () => {
      const inputs = EMBARRASSMENT_CORPUS.map((e) => e.input);
      expect(inputs.length).toBe(new Set(inputs).size);
    });

    it("gives every entry a rationale", () => {
      for (const entry of EMBARRASSMENT_CORPUS) {
        expect(entry.why.trim().length, `${entry.input}: empty rationale`).toBeGreaterThan(0);
      }
    });

    it("points every pending entry at a tracked issue", () => {
      for (const entry of PENDING_ENTRIES) {
        expect(entry.pendingIssue, `${entry.input}: malformed issue id`).toMatch(/^LINK-[a-z]+$/);
      }
    });

    it("keeps at least one active guard, so the suite cannot pass vacuously", () => {
      expect(ACTIVE_ENTRIES.length).toBeGreaterThan(0);
    });

    it("does not list an accepted out-of-scope string as a corpus entry", () => {
      const inputs = new Set(EMBARRASSMENT_CORPUS.map((e) => e.input));
      for (const accepted of KNOWN_AND_ACCEPTED) {
        expect(inputs.has(accepted), `${accepted} is both accepted and asserted`).toBe(false);
      }
    });
  });
});
