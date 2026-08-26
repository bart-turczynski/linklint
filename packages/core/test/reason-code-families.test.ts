import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * LINK-tviundio — reason-code correlation families.
 *
 * The observation that motivated the taxonomy: one edit to a URL can raise
 * several reason codes, and `reasons[]` then reads to a triager as several
 * separate problems when the underlying evidence is one. `apple.com` with its
 * leading `a` replaced by CYRILLIC SMALL LETTER A (U+0430) is the worked case —
 * a single code point, four scoring codes and two informational ones.
 *
 * This block pins the observation itself, before any taxonomy exists, so the
 * partition that follows is anchored on measured behavior rather than on a
 * recollection of it. Under probabilistic-OR the score saturates either way;
 * what the correlation distorts is the explanation, which is the product.
 */

/** `apple.com` with U+0430 in place of the leading ASCII `a`. */
const CYRILLIC_APPLE = "https://аpple.com/";

function codesOf(url: string, options: Parameters<typeof inspect>[1] = {}): string[] {
  return inspect(url, options).reasons.map((r) => r.code);
}

function scoringCodesOf(url: string, options: Parameters<typeof inspect>[1] = {}): string[] {
  return inspect(url, options)
    .reasons.filter((r) => r.weight > 0)
    .map((r) => r.code);
}

describe("one edit, many codes — the correlation the families describe", () => {
  it("the unmodified host is clean, so the whole reason list is attributable to one code point", () => {
    const clean = inspect("https://apple.com/");
    expect(clean.status).toBe("ok");
    expect(clean.reasons).toEqual([]);
    expect(clean.score).toBe(0);
  });

  it("one Cyrillic code point raises exactly four scoring codes", () => {
    expect(scoringCodesOf(CYRILLIC_APPLE)).toEqual([
      "homograph_latin_skeleton",
      "mixed_script",
      "idn_host",
      "homograph_skeleton_collision",
    ]);
  });

  it("the same code point also raises two weight-0 codes, for six reasons off one character", () => {
    expect(codesOf(CYRILLIC_APPLE)).toEqual([
      "homograph_latin_skeleton",
      "mixed_script",
      "idn_host",
      "homograph_skeleton_collision",
      "confusable_char",
      "normalization_delta",
    ]);
  });

  it("saturating aggregation hides the correlation in the score but not in the explanation", () => {
    const result = inspect(CYRILLIC_APPLE);
    expect(result.score).toBe(1);
    expect(result.severity).toBe("critical");
    // A weight-1 code alone already lands here, so the other three move nothing.
    expect(result.reasons.filter((r) => r.weight === 1).length).toBeGreaterThan(0);
  });

  it("one ASCII digit substitution raises two codes on a pure-ASCII host", () => {
    expect(codesOf("https://paypal.com/")).toEqual([]);
    expect(codesOf("https://paypa1.com/")).toEqual(["brand_homoglyph", "ascii_homoglyph"]);
  });

  /**
   * The escape pair behaves differently from the two clusters above and is
   * pinned so the taxonomy is not written against a guess. `encoding_obfuscation`
   * and `percent_encoding_malformed` read the same feature — the percent-escape
   * sequence — but they read it to opposite conclusions, so a single escape
   * raises one or the other rather than both. Codes that share a feature and
   * exclude each other are still correlated evidence: seeing the second tells a
   * triager nothing the first did not already rest on.
   */
  it("one escape raises one of the two escape codes, not both", () => {
    expect(codesOf("https://example.com/a%2fb")).toEqual(["encoding_obfuscation"]);
    expect(codesOf("https://example.com/a%252fb")).toEqual(["encoding_obfuscation"]);
    expect(codesOf("https://example.com/a%2")).toEqual(["percent_encoding_malformed"]);
    expect(codesOf("https://example.com/a%zzb")).toEqual(["percent_encoding_malformed"]);
  });

  /**
   * The other direction, which the tie-break in `docs/reason-codes.md` turns on:
   * escaping one control character raises codes that read the escape AND codes
   * that read the byte it decodes to, so an edit can touch two features at once.
   */
  it("escaping one control character raises codes from more than one feature", () => {
    const codes = codesOf("https://example.com/x?a=1%0d%0aHost:%20evil");
    expect(codes).toContain("encoding_obfuscation");
    expect(codes).toContain("control_char");
    expect(codes).toContain("header_shaped_token");
  });

  it("each of those two features is reachable without the other", () => {
    // An escape that hides a delimiter, with no control byte anywhere.
    expect(codesOf("https://example.com/a%2fb")).toEqual(["encoding_obfuscation"]);
    // A raw control character, with no escape anywhere.
    const raw = codesOf("https://example.com/x?a=1\rHost: evil");
    expect(raw).toContain("control_char");
    expect(raw).not.toContain("encoding_obfuscation");
  });
});
