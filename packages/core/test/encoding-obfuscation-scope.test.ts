import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * LINK-dlcyzghg — where `encoding_obfuscation` looks, and why.
 *
 * The detector carries six signals with two different scopes, and the split was
 * an accident of implementation until this ticket made it a decision. These
 * tests pin the decision so the next reader finds it enforced rather than
 * asserted in prose.
 *
 * PATH-SCOPED: the encoded separator (`%2F`, `%5C`) and the encoded `..`
 * traversal. WHOLE-URL: double-encoding, >=3-level nesting, overlong UTF-8, and
 * encoded control characters — these reach the userinfo too.
 *
 * The userinfo exclusion is grammatical, not incidental. RFC 3986 3.2.1 gives
 * `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`, and `/` is not
 * in that set, so a slash in a userinfo MUST be percent-encoded to be legal.
 * `%2F` there is compliance with the grammar, not concealment of a delimiter.
 * In a path `/` is legal unencoded and is the segment separator, so `%2F` is a
 * delimiter deliberately stopped from acting as one — that asymmetry is the
 * signal.
 *
 * The exclusion is NOT justified by `userinfo_present` (0.5) outweighing this
 * code (0.35): aggregation is probabilistic-OR, not max, so the widening would
 * cross a severity band. That is asserted directly below, because it is the
 * argument the ticket was originally filed on and it does not hold.
 */

const codes = (url: string) => inspect(url).reasons.map((r) => r.code);

describe("encoding_obfuscation — the four whole-URL signals reach the userinfo", () => {
  it.each([
    ["https://user%252e@example.com/", "double-encoded (%25)"],
    ["https://user%01@example.com/", "encoded control character"],
  ])("%s fires, and names the signal it found", (url, signal) => {
    const reason = inspect(url).reasons.find((r) => r.code === "encoding_obfuscation");
    expect(reason, `${url} should fire encoding_obfuscation`).toBeDefined();
    expect(reason?.detail).toContain(signal);
  });
});

describe("encoding_obfuscation — the separator signal is path-scoped", () => {
  it("fires on an encoded separator in the path", () => {
    expect(codes("https://evil.com/redirect%2F..%2Fadmin")).toContain("encoding_obfuscation");
  });

  it.each([
    ["https://user%2F@example.com/", "encoded / in the userinfo — RFC 3986 requires the encoding"],
    ["https://user%5C@example.com/", "encoded backslash, same grammar"],
    ["https://example.com/?redir=a%2Fb", "encoded / in a query value — legitimate encoding"],
  ])("%s stays silent (%s)", (url) => {
    expect(codes(url)).not.toContain("encoding_obfuscation");
  });
});

describe("encoding_obfuscation — the userinfo exclusion is load-bearing, not moot", () => {
  // The ticket's original premise was that userinfo_present (0.5) already
  // outweighs this code (0.35), so matching there would change nothing. It
  // would: probabilistic-OR aggregation compounds the two.
  const legitimate = "https://user:p%2Fss@example.com/"; // a password containing a slash

  it("a slash in a password is a correctly-formed URL that stays at medium", () => {
    const result = inspect(legitimate);
    expect(result.reasons.map((r) => r.code)).toEqual(["userinfo_present"]);
    expect(result.severity).toBe("medium");
  });

  it("adding this code to the same host would cross into high — so 'it is moot' is false", () => {
    // Same two weights, reached via a path-scoped hit rather than a userinfo one.
    const both = inspect("https://user@example.com/a%2Fb");
    expect(both.reasons.map((r) => r.code).sort()).toEqual([
      "encoding_obfuscation",
      "userinfo_present",
    ]);
    expect(both.severity).toBe("high");
    expect(both.score).toBeGreaterThan(inspect(legitimate).score ?? 0);
  });
});
