/**
 * LINK-crxctgsh — the closing-comment predicate behind the fp `done` guard.
 *
 * The fp runtime wiring in `tools/fp-extensions/closing-comment-required/index.ts`
 * cannot be exercised here (it needs the fp extension host), so the branch
 * coverage lives on the pure predicate. The wiring itself is one `to !== "done"`
 * guard plus a `comments.some(...)`, smoke-tested by hand against the CLI.
 */
import { describe, expect, it } from "vitest";
import { isClosingComment } from "../../tools/fp-extensions/closing-comment-required/predicate.js";

describe("isClosingComment", () => {
  it("accepts the repo's established 'merged as PR #N' convention", () => {
    expect(isClosingComment("merged as PR #139")).toBe(true);
    expect(isClosingComment("Epic slice complete. Shipped: #44, #45, #46.")).toBe(true);
    expect(isClosingComment("closed by pull request 7")).toBe(true);
  });

  it("accepts a commit SHA", () => {
    expect(isClosingComment("landed in 71debd9")).toBe(true);
    expect(isClosingComment("see 10d5369b8a4f2e1c9d0a")).toBe(true);
  });

  it("accepts an exemption that states a reason", () => {
    expect(isClosingComment("NO-COMMIT: declined on cost, see the analysis above")).toBe(true);
  });

  it("rejects an exemption with no reason, so the hatch stays auditable", () => {
    expect(isClosingComment("NO-COMMIT:")).toBe(false);
    expect(isClosingComment("NO-COMMIT:   ")).toBe(false);
  });

  it("rejects progress comments that reference nothing", () => {
    expect(isClosingComment("did some work here")).toBe(false);
    expect(isClosingComment("")).toBe(false);
    expect(isClosingComment("Probed on 2026-07-26; nine closed as already covered.")).toBe(false);
  });

  it("does not read a bare number as a commit", () => {
    // The corpus and audit comments are full of these.
    expect(isClosingComment("1234567 URLs in the corpus")).toBe(false);
    expect(isClosingComment("fires 59/239 and is ~90% false positive")).toBe(false);
    expect(isClosingComment("scores 0.35, above the band")).toBe(false);
  });

  it("does not read a markdown heading as a PR reference", () => {
    expect(isClosingComment("# 1 Summary")).toBe(false);
    expect(isClosingComment("## 2 Findings")).toBe(false);
  });

  it("does not read a short hex-looking word as a SHA", () => {
    // Under 7 chars, so not a SHA by length.
    expect(isClosingComment("added a decade of data")).toBe(false);
    expect(isClosingComment("the beef is in the detector")).toBe(false);
  });
});
