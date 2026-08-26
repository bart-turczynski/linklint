import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { BEST_FIT_SOURCES } from "../src/detectors/best-fit-mapping.js";

// LINK-bmnluefn (T2.1) — COMMIT 2 of 2. The previous commit pinned this gap
// OPEN: each payload below returned 0.00/info with an EMPTY reason list, which
// under docs/architecture.md §1.1's fourth rule asserts "there is nothing to say
// about this URL". The diff of this file carries the before and the after.
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
// file that did NOT change across the two commits, which is what shows the gate
// is on the neighbourhood the materialized character would land in rather than
// on the bare character.

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

describe("best-fit charset mappings in path/query are detected (LINK-bmnluefn)", () => {
  it.each(PAYLOADS)("%s (%s) reaches 0.50/medium on this code alone", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0.5);
    expect(r.severity).toBe("medium");
    expect(r.reasons.map((x) => x.code)).toEqual(["best_fit_mapping"]);
  });

  it("the detail names the code point, the ASCII it becomes, and the grammar", () => {
    const yen = inspect("https://example.com/path¥win").reasons[0]!;
    expect(yen.detail).toContain("U+00A5");
    expect(yen.detail).toContain("codepage 932");
    expect(yen.detail).toContain("Windows path separator");
    expect(yen.detail).toContain("in path");

    const quote = inspect("https://example.com/?q=＂x＂").reasons[0]!;
    expect(quote.detail).toContain("U+FF02");
    expect(quote.detail).toContain("command-line quote delimiter");
    expect(quote.detail).toContain("in query");
  });

  it("registers at weight 0.50 as a scoring lexical code", () => {
    expect(REASON_CODES.best_fit_mapping).toMatchObject({
      layer: "lexical",
      scoring: true,
      weight: 0.5,
    });
  });
});

describe("benign placement stays quiet (the measured false-positive profile)", () => {
  it.each(CONTROLS)("%s (%s) raises no best-fit finding", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).not.toContain("best_fit_mapping");
  });

  it("a fragment is out of scope — it is not sent to a server", () => {
    const codes = inspect("https://example.com/#path¥win").reasons.map((x) => x.code);
    expect(codes).not.toContain("best_fit_mapping");
  });

  it("a pure-ASCII path or query holds no best-fit source", () => {
    for (const url of [
      "https://example.com/path/win",
      "https://example.com/?q=Host:%20evil.com",
      "https://example.com/",
    ]) {
      expect(inspect(url).reasons.map((x) => x.code), url).not.toContain("best_fit_mapping");
    }
  });
});

describe("the guard is placement, not membership — the recorded decisions hold", () => {
  // `packages/core/src/detectors/separator-lookalike.ts` excludes path and query
  // ON PURPOSE, because an ideographic full stop is ordinary CJK punctuation
  // inside a path segment. This block is the proof that nothing here reopened
  // that: the same character in the same position is quiet under both codes.
  it("U+3002 is not a best-fit source at all — it has an exact codepage mapping", () => {
    expect(BEST_FIT_SOURCES.has(0x3002)).toBe(false);
    const codes = inspect("https://example.com/記事。html").reasons.map((x) => x.code);
    expect(codes).not.toContain("best_fit_mapping");
    expect(codes).not.toContain("separator_lookalike");
  });

  it("U+FF0F IS a source, and the guard is what keeps CJK prose quiet", () => {
    expect(BEST_FIT_SOURCES.has(0xff0f)).toBe(true);
    // Same character, two neighbourhoods. Non-ASCII text on one side is prose.
    expect(inspect("https://example.com/記事／html").reasons.map((x) => x.code)).not.toContain(
      "best_fit_mapping",
    );
    // ASCII letters on both sides is a segment boundary the URL declines to declare.
    expect(inspect("https://example.com/path／win").reasons.map((x) => x.code)).toContain(
      "best_fit_mapping",
    );
  });

  it("curly quotes and the soft hyphen are outside the table on purpose", () => {
    for (const code of [0x2018, 0x2019, 0x201c, 0x201d, 0x00ad]) {
      expect(BEST_FIT_SOURCES.has(code), code.toString(16)).toBe(false);
    }
    // The soft hyphen's shape is covered by a stronger code already.
    expect(inspect("https://example.com/pa­th").reasons.map((x) => x.code)).toContain(
      "invisible_char",
    );
  });

  it("a digit neighbour is not a letter neighbour — prices stay quiet", () => {
    expect(inspect("https://example.com/?price=¥1000").reasons).toEqual([]);
    expect(inspect("https://example.com/?p=¥share").reasons.map((x) => x.code)).toEqual([
      "best_fit_mapping",
    ]);
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

  it("low_byte_truncation does not reach these code points", () => {
    // The neighbouring code covers a DIFFERENT lossy conversion (UTF-16 narrowed
    // to its low byte). U+00A5's low byte is 0xA5 and U+FF3C's is 0x3C; neither
    // is in its dangerous-byte set, so the two codes do not overlap.
    for (const [url] of PAYLOADS) {
      expect(inspect(url).reasons.map((x) => x.code), url).not.toContain("low_byte_truncation");
    }
  });
});
