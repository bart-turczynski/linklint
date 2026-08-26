import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-bmnluefn (T2.1) — COMMIT 1 of 2. This file pins the gap OPEN.
//
// Every payload below returns 0.00 / info with an EMPTY reason list, which
// under docs/architecture.md §1.1's fourth rule is the strongest thing the
// result contract can say: there is nothing to report about this URL. The diff
// of this file in the next commit carries the before and the after.
//
// The mechanism is a CONVERSION, not an appearance. On Windows, a string handed
// to `WideCharToMultiByte` for an ANSI codepage without `WC_NO_BEST_FIT_CHARS`
// has code points with no exact representation replaced by a "best fit" ASCII
// character from a published vendor table. U+00A5 YEN SIGN becomes `\` under
// codepage 932, because JIS X 0201 puts the yen sign at 0x5C; U+20A9 WON SIGN
// becomes `\` under codepage 949 for the same reason; the fullwidth forms
// collapse onto their ASCII counterparts. So a character inert to a URL parser
// becomes a Windows path separator, a quote, or a query delimiter inside the
// consuming process. Orange Tsai, "WorstFit", Black Hat EU 2024; CVE-2024-4577
// is the disclosed consequence class.
//
// The CONTROLS section is the false-positive profile. It is the half of this
// file that does NOT change in the next commit, which is what shows the gate is
// on the neighbourhood the materialized character would land in rather than on
// the bare character.

/** Path/query surfaces where the conversion would materialize a delimiter. */
const PAYLOADS: ReadonlyArray<readonly [string, string]> = [
  ["https://example.com/path¥win", "U+00A5 -> '\\' under codepage 932 (JIS X 0201 0x5C)"],
  ["https://example.com/path₩win", "U+20A9 -> '\\' under codepage 949 (KS X 1003 0x5C)"],
  ["https://example.com/path＼win", "U+FF3C fullwidth reverse solidus -> '\\'"],
  ["https://example.com/path／win", "U+FF0F fullwidth solidus -> '/'"],
  ["https://example.com/?q=＂x＂", "U+FF02 fullwidth quotation mark -> '\"'"],
  ["https://example.com/?p=¥share", "U+00A5 in a query value, introducing a UNC-ish segment"],
];

/**
 * Rows that stay quiet in BOTH commits. Two families:
 *
 *  1. The character used for what it is — a currency sign beside digits is a
 *     price, not a path separator.
 *  2. The character sitting in non-ASCII prose. `separator_lookalike` ignores
 *     path and query on purpose, and `/記事。html` is the counterexample its
 *     own header cites. Nothing here may disturb that.
 */
const CONTROLS: ReadonlyArray<readonly [string, string]> = [
  ["https://example.com/?price=¥1000", "yen sign beside digits — ordinary currency use"],
  ["https://example.com/?price=1000¥", "same, trailing"],
  ["https://example.com/?price=￥1200&x=1", "fullwidth yen beside digits"],
  ["https://example.com/記事／html", "fullwidth solidus inside CJK prose"],
  ["https://example.com/記事。html", "the ideographic full stop separator_lookalike protects"],
  ["https://example.com/?title=“hello”", "curly quotes are ordinary orthography"],
  ["https://example.com/?q=日本語", "a pure CJK query value"],
  ["https://example.com/path/win", "the plain ASCII spelling of the first payload"],
];

describe("best-fit charset mappings in path/query are NOT detected yet (LINK-bmnluefn)", () => {
  it.each(PAYLOADS)("%s (%s) is 0.00/info with nothing to say", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons).toEqual([]);
  });
});

describe("the false-positive profile — these stay quiet across both commits", () => {
  it.each(CONTROLS)("%s (%s) raises nothing", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.severity).toBe("info");
  });
});

describe("what already covers the neighbouring surfaces", () => {
  // Re-derived rather than trusted, because it is the reason the new code is
  // scoped to path and query.
  it("a yen sign in the HOST is fail-closed invalid, not silently passed", () => {
    const r = inspect("https://exam¥ple.com/");
    expect(r.status).toBe("invalid");
    expect(r.score).toBeNull();
  });

  it("a fullwidth solidus in the AUTHORITY is already separator_lookalike", () => {
    const codes = inspect("https://github.com／x@evil.zip/").reasons.map((x) => x.code);
    expect(codes).toContain("separator_lookalike");
  });

  it("a soft hyphen in the path is already invisible_char at weight 1", () => {
    // U+00AD best-fits to '-', which is why '-' is deliberately outside the new
    // table: the shape is covered, and a hyphen in a path is unremarkable.
    const r = inspect("https://example.com/pa­th");
    expect(r.reasons.map((x) => x.code)).toContain("invisible_char");
    expect(r.score).toBe(1);
  });

  it("low_byte_truncation does not reach these code points", () => {
    // The neighbouring code covers a DIFFERENT lossy conversion (UTF-16 narrowed
    // to its low byte). U+00A5's low byte is 0xA5 and U+FF3C's is 0x3C; neither
    // is in its dangerous-byte set, so the two codes do not overlap.
    for (const [url] of PAYLOADS) {
      expect(inspect(url).reasons.map((x) => x.code), url).not.toContain("low_byte_truncation");
    }
  });
});
