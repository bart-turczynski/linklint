import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const homoglyphDetail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_homoglyph")?.detail ?? "";

describe("G2 brand_homoglyph — digit-fold skeleton equals a known brand (high confidence)", () => {
  it("paypa1.com folds to paypal.com and names the brand + the fold", () => {
    expect(codes("https://paypa1.com")).toContain("brand_homoglyph");
    const d = homoglyphDetail("https://paypa1.com");
    expect(d).toContain("paypa1.com");
    expect(d).toContain("paypal.com");
    expect(d).toContain("0->o"); // mentions the fold mapping
  });

  it("g00gle.com folds to google.com", () => {
    expect(codes("https://g00gle.com")).toContain("brand_homoglyph");
    expect(homoglyphDetail("https://g00gle.com")).toContain("google.com");
  });

  it("revo1ut.com folds to revolut.com", () => {
    expect(codes("https://revo1ut.com")).toContain("brand_homoglyph");
    expect(homoglyphDetail("https://revo1ut.com")).toContain("revolut.com");
  });

  it("carries the high brand-impersonation weight (0.5)", () => {
    const reason = inspect("https://paypa1.com").reasons.find(
      (x) => x.code === "brand_homoglyph",
    )!;
    expect(reason.weight).toBeCloseTo(0.5, 5);
  });

  it("the real brand never fires brand_homoglyph", () => {
    expect(codes("https://paypal.com/login")).not.toContain("brand_homoglyph");
    expect(codes("https://google.com/")).not.toContain("brand_homoglyph");
  });

  it("a non-brand digit-homoglyph skeleton does NOT fire (no exact brand match)", () => {
    // `c00kie` -> `cookie`, a real word but not a watchlist brand.
    expect(codes("https://c00kie.com")).not.toContain("brand_homoglyph");
    // `s3`/`route53`/`bet365` never fold to a brand (2/3/6 are not letter-shapes).
    expect(codes("https://route53.com")).not.toContain("brand_homoglyph");
    expect(codes("https://bet365.com")).not.toContain("brand_homoglyph");
  });
});

describe("G2 — structurally-clean near-misses are NOT findings (LINK-cphogucn)", () => {
  // The deleted `brand_lookalike` step fired on strings where
  // normalize(input) === input — pure ASCII, single script, no digit fold. Under
  // claim (a) the watchlist may only NAME an independently-detected structural
  // anomaly, never CREATE a finding, so these are silent by design.
  const clean = [
    "https://paypai.com/", // substitution, no fold
    "https://gogole.com/", // transposition of google
    "https://microsoftt.com/", // insertion on a long brand
    "https://paypal.co/", // TLD swap
    "https://mecrosfot.com/", // distance-2 typo of microsoft
    "https://netflicks.com/", // former brand_soundsquat
    "https://dropboks.com/", // former brand_soundsquat
    "https://netfliz.com/", // former brand_bitsquat
    "https://amazgn.com/", // former brand_bitsquat
    "https://anthropics.com/", // real UK business, formerly a distance-1 false positive
  ];
  for (const input of clean) {
    it(`${JSON.stringify(input)} scores 0.00 with no brand reason`, () => {
      const result = inspect(input);
      expect(result.reasons.map((r) => r.code)).not.toContain("brand_homoglyph");
      expect(result.score).toBe(0);
    });
  }
});

describe("G2 — exact-brand negatives (the real brand never fires)", () => {
  const exact = [
    "https://paypal.com/login",
    "https://www.google.com/",
    "https://mail.google.com/", // registrable is google.com (exact)
    "https://github.com/anthropics/repo",
    "https://microsoft.com/",
  ];
  for (const input of exact) {
    it(`no brand code for the real brand ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("brand_homoglyph");
    });
  }
});

describe("G2 — non-host negatives", () => {
  it("does not fire on an IP host", () => {
    expect(codes("http://127.0.0.1/")).not.toContain("brand_homoglyph");
    expect(codes("http://2130706433/")).not.toContain("brand_homoglyph");
  });

  it("does not fire on empty / unparseable input (no registrable domain)", () => {
    expect(codes("   ")).not.toContain("brand_homoglyph");
  });

  it("does not fire on an unrelated, distant domain", () => {
    expect(codes("https://example.com/")).not.toContain("brand_homoglyph");
  });
});
