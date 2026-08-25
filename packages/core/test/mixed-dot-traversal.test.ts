import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * LINK-dpahotkg — the encoded double-dot path segment, all four spellings.
 *
 * PIN COMMIT. Everything in this file asserts what the detector does TODAY,
 * including the part that is wrong, so the next commit has to change an
 * executable statement rather than an opinion.
 *
 * The WHATWG URL Standard enumerates a "double-dot path segment" by name and by
 * exhaustive list: `..`, `.%2e`, `%2e.`, `%2e%2e`, ASCII case-insensitive. Every
 * conforming parser pops the parent for all four. `encoding_obfuscation`
 * implements the fourth and omits the second and third, so three of the four
 * spellings the standard names score 0 / info / no reasons.
 *
 * This is architecture §1.1's path rule applied, not widened: the divergence is
 * enumerated by the URL standard itself, so it is a property of the string and
 * settleable offline by anyone holding the spec. No server behavior is assumed.
 * It is form 1 (`normalize(input) !== input` — the segment reads as literal text
 * and resolves as a traversal) and form 2 (an allowlist string-matching for `..`
 * and a conforming fetcher reach different destinations).
 */

const codes = (url: string) => inspect(url).reasons.map((r) => r.code);
const detail = (url: string) =>
  inspect(url).reasons.find((r) => r.code === "encoding_obfuscation")?.detail ?? "";

/**
 * Ground truth, independent of linklint: Node's own WHATWG URL parser. These
 * assertions are green on both sides of the fix by design — they pin the SPEC,
 * not the detector, and they are what makes the next commit's expectation flip
 * a correction rather than a preference.
 */
describe("SPEC — every WHATWG double-dot spelling pops the parent (ground truth)", () => {
  it.each([
    ["https://example.com/a/../admin", "unencoded"],
    ["https://example.com/a/.%2e/admin", "trailing dot encoded"],
    ["https://example.com/a/%2e./admin", "leading dot encoded"],
    ["https://example.com/a/%2e%2e/admin", "both dots encoded"],
    ["https://example.com/a/.%2E/admin", "uppercase hex"],
    ["https://example.com/a/%2E%2E/admin", "both uppercase"],
  ])("%s (%s) resolves to /admin", (url) => {
    expect(new URL(url).pathname).toBe("/admin");
  });

  it("the enumeration is exact — a segment that merely CONTAINS %2e is not a double-dot segment", () => {
    // `.%2e%2e` is not on the list, so no parser pops for it.
    expect(new URL("https://example.com/a/.%2e%2e/admin").pathname).toBe("/a/.%2e%2e/admin");
    // `%2e%2e` inside a longer segment is a filename, not a traversal.
    expect(new URL("https://example.com/docs/file%2e%2etxt").pathname).toBe("/docs/file%2e%2etxt");
    // An encoded separator is NOT a separator to a conforming parser, so this
    // is one long segment and nothing pops.
    expect(new URL("https://example.com/%2e%2e%2fadmin").pathname).toBe("/%2e%2e%2fadmin");
  });
});

describe("THE GAP (pinned as-is) — three of the four spellings are silent today", () => {
  it.each([
    ["https://example.com/a/.%2e/admin"],
    ["https://example.com/a/%2e./admin"],
    ["https://example.com/a/.%2E/admin"],
  ])("%s scores 0 / info / no reasons", (url) => {
    const r = inspect(url);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons).toEqual([]);
  });
});

describe("MUST NOT REGRESS — the fourth spelling already fires", () => {
  it("a bare %2e%2e segment fires and names the traversal", () => {
    const url = "https://example.com/a/%2e%2e/admin";
    expect(inspect(url).score).toBe(0.35);
    expect(inspect(url).severity).toBe("medium");
    expect(codes(url)).toContain("encoding_obfuscation");
    expect(detail(url)).toContain("encoded '..' traversal");
  });

  it("an uppercase %2E%2E segment fires too — the match is case-insensitive", () => {
    expect(codes("https://example.com/a/%2E%2E/admin")).toContain("encoding_obfuscation");
  });

  it("the composite %2e%2e%2f shape still fires (it carries an encoded separator)", () => {
    expect(codes("https://example.com/%2e%2e%2fadmin")).toContain("encoding_obfuscation");
    expect(codes("https://example.com/%2e%2e%2f%2e%2e%2fadmin")).toContain("encoding_obfuscation");
  });
});

/**
 * PRE-EXISTING INCONSISTENCY, pinned before it is decided. The shipped `%2e%2e`
 * rule is a substring match, so it fires on a segment that merely contains the
 * pair — a filename that decodes to `file..txt`, which no conforming parser
 * treats as a traversal. Pinned here so the next commit's decision about it is
 * visible as a diff.
 */
describe("PRE-EXISTING — the shipped %2e%2e rule is substring-based", () => {
  it("fires on an encoded-dot FILENAME that no parser pops", () => {
    const url = "https://example.com/docs/file%2e%2etxt";
    expect(codes(url)).toContain("encoding_obfuscation");
    expect(detail(url)).toContain("encoded '..' traversal");
  });
});

/**
 * GUARDS against the rejected alternative. A substring rule for the mixed
 * spellings — `/\.%2e|%2e\./i` — hits all four of these, none of which any
 * parser pops. They are green today and stay green after the fix, so across the
 * shipped diff they are CONTROLS, not proof. What they are proof of is the
 * design choice: mutate the detector to the substring form and all four go red,
 * which is the measurement that rejected it.
 *
 * A segment-bounded rule cannot reach a filename by construction. A segment that
 * is exactly `.%2e` IS `..` to every conforming reader — it is not a filename at
 * all, so there is no filename for the rule to hit.
 */
describe("GUARD — encoded-dot filenames must stay silent (controls across the fix)", () => {
  it.each([
    ["https://example.com/files/report%2e.pdf", "report..pdf"],
    ["https://example.com/dl/My%20File%2e.txt", "My File..txt"],
    ["https://example.com/pkg/lodash%2e.min.js", "lodash..min.js"],
    ["https://example.com/x/.%2ehidden/file", "...hidden as a dotfile name"],
    ["https://example.com/docs/v1%2e2/guide", "an encoded dot in a version"],
    ["https://example.com/u/john%2edoe/profile", "an encoded dot in a username"],
    ["https://example.com/static/jquery%2emin%2ejs", "encoded dots in a bundle name"],
    ["https://example.com/repo/tree/main/%2egithub/workflows", "an encoded leading dot"],
  ])("%s (%s) scores 0 / info / no reasons", (url) => {
    const r = inspect(url);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons).toEqual([]);
  });
});
