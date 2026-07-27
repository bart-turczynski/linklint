import { describe, expect, it } from "vitest";
import {
  classifyClosingComment,
  isClosingComment,
  isTombstoneTitle,
} from "../../../tools/fp-extensions/closing-comment-required/predicate.js";

/**
 * The closing-comment predicate (LINK-crxctgsh), under test at last.
 *
 * Its own docstring claimed it was "kept free of any `@fiberplane/extensions`
 * import so it typechecks and unit-tests inside the repo's normal `pnpm check`
 * chain" — true of the first half and false of the second: no test imported it
 * and `tools/` was outside the tsconfig globs. That is the same
 * prose-outrunning-code shape `docs/guarantees.md` exists to catch, in the file
 * whose whole job is catching it.
 *
 * The classification split matters (LINK-nwqrqjdc). A PR reference or a stated
 * exemption discharges the requirement on its own, because the evidence lives
 * somewhere this guard cannot reach. A bare SHA does NOT: it has to be verified
 * reachable from the trunk, which is the check whose absence let twelve issues
 * close on commits nobody ever merged. Reachability itself is `index.ts`'s job
 * (it needs git); what is pinned here is that the predicate routes a bare SHA
 * into that check instead of waving it through.
 */

describe("closing-comment predicate — what discharges the requirement", () => {
  it.each([
    ["merged as PR #139", "pr"],
    ["landed in pull request 42", "pr"],
    ["see #7 for the follow-up", "pr"],
    ["NO-COMMIT: declined on cost, see the analysis above", "exempt"],
    ["landed in 71debd9", "sha"],
    ["merged as aa3b054 and f1abd9c", "sha"],
  ] as const)("%s → %s", (content, kind) => {
    expect(classifyClosingComment(content).kind).toBe(kind);
    expect(isClosingComment(content)).toBe(true);
  });

  it.each([
    ["done!", "no reference at all"],
    ["shipped, see the branch", "a branch is not a commit"],
    ["1234567 URLs in the corpus", "a bare number is not a SHA"],
    ["NO-COMMIT:", "an exemption with no stated reason"],
  ])("%s does not discharge it (%s)", (content) => {
    expect(classifyClosingComment(content).kind).toBe("none");
    expect(isClosingComment(content)).toBe(false);
  });
});

describe("closing-comment predicate — a bare SHA is routed to verification", () => {
  it("returns every SHA it found, so index.ts can check them all", () => {
    const verdict = classifyClosingComment("merged as aa3b054, then fixed in f1abd9c");
    expect(verdict.kind).toBe("sha");
    expect(verdict.shas).toEqual(["aa3b054", "f1abd9c"]);
  });

  it.each([
    ["merged as PR #139 (landed in 71debd9)", "pr"],
    ["NO-COMMIT: superseded — the old attempt was 71debd9", "exempt"],
  ] as const)("%s outranks the SHA it also mentions", (content, kind) => {
    const verdict = classifyClosingComment(content);
    expect(verdict.kind).toBe(kind);
    // Nothing to verify: the merge or the stated reason is the evidence.
    expect(verdict.shas).toEqual([]);
  });
});

describe("tombstone titles close without a comment (LINK-owjeewpe)", () => {
  it.each(["[SCRATCHED] never merged", "[SUPERSEDED] by LINK-tqlqshlt"])("%s", (title) => {
    expect(isTombstoneTitle(title)).toBe(true);
  });

  it.each([
    ["[PARKED] not started", "parked work stays todo, so it never reaches this gate"],
    ["Rename the check id", "an ordinary title"],
  ])("%s is not a tombstone (%s)", (title) => {
    expect(isTombstoneTitle(title)).toBe(false);
  });
});
