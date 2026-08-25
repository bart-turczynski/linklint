import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * LINK-iuzphbnp — architecture §1.1's fourth rule: "where a `parse_error` is
 * unavoidable, it names what failed rather than standing in for the whole
 * verdict."
 *
 * This file is the pin for that rule on the scheme-bearing invalid path. It is
 * committed FIRST in its pre-fix state, recording what the shipped serializer
 * actually says today, so the change that follows is visible as a diff of
 * assertions rather than as a claim in a commit message.
 *
 * Two halves, and both matter:
 *
 *   1. THE DETAIL. `mhtml:…!x-usc:…`, `ms-appinstaller:?source=…` and
 *      `view-source:https://…` each carry a single `parse_error` whose detail
 *      is the module-level fallback string — the caller is not told which
 *      scheme was read or why the body went uninspected.
 *   2. THE VERDICT. Status, score, severity and the reason CODES for the same
 *      inputs. §1.1's fourth rule is a reporting obligation, not a widening of
 *      claim (a): whatever the detail ends up saying, these must not move.
 *      A reviewer reads this half to confirm the change is explanatory only.
 */

/** The scheme-bearing inputs the fourth rule is failing on. */
const SCHEME_BEARING = [
  ["mhtml archive with an x-usc redirect", "mhtml:https://example.com/a.mhtml!x-usc:https://evil.test/"],
  ["ms-appinstaller with a remote source", "ms-appinstaller:?source=https://evil.test/app.appinstaller"],
  ["view-source wrapping an https URL", "view-source:https://example.com/"],
] as const;

/**
 * The fallback the serializer emits when nothing sharpens the message. Written
 * out literally rather than imported, so a change to the constant shows up here
 * as a failure instead of being tracked silently.
 */
const GENERIC = "input is not a parseable URL or hostname";

describe("parse_error detail on scheme-bearing input (LINK-iuzphbnp)", () => {
  it.each(SCHEME_BEARING)(
    "%s: the detail is the generic fallback, naming nothing",
    (_label, url) => {
      const result = inspect(url);
      expect(result.reasons).toHaveLength(1);
      expect(result.reasons[0]!.code).toBe("parse_error");
      // The defect: the scheme that was read appears nowhere in the message.
      expect(result.reasons[0]!.detail).toBe(GENERIC);
    },
  );
});

describe("verdicts on the scheme-bearing invalid path do not move (LINK-iuzphbnp)", () => {
  it.each(SCHEME_BEARING)("%s: fail-closed shape is exactly as shipped", (_label, url) => {
    const result = inspect(url);
    expect(result.status).toBe("invalid");
    expect(result.score).toBeNull();
    expect(result.severity).toBeNull();
    expect(result.parsed).toBeNull();
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
    expect(result.reasons.map((r) => r.weight)).toEqual([0]);
    expect(result.checksRun).toEqual([]);
    expect(result.checksSkipped).toEqual(["lexical", "resolution", "reputation"]);
  });

  it("a schemeless parse failure keeps the generic fallback", () => {
    // The counterweight to the sharpening that follows: with no scheme token
    // there is nothing to name, so this input's detail is the one that must
    // stay put. `non-string-input.test.ts` pins the same string for
    // "not a url at all"; this is the cucumber-pinned SC-2a vector.
    const result = inspect("ht!tp://%%%not a url");
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
    expect(result.reasons[0]!.detail).toBe(GENERIC);
  });

  it("a non-string input keeps its own sharpened detail", () => {
    // The existing occupant of the `parseErrorDetail` channel. Populating the
    // channel from the parse path must not displace the caller-contract case.
    const result = inspect(null as unknown as string);
    expect(result.reasons[0]!.detail).toContain("not a string");
  });
});
