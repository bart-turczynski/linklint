import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const homoglyphDetail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_homoglyph")?.detail ?? "";
const lookalikeDetail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_lookalike")?.detail ?? "";

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

  it("does NOT also emit brand_lookalike for the same input (no double-report)", () => {
    const found = codes("https://paypa1.com");
    expect(found).toContain("brand_homoglyph");
    expect(found).not.toContain("brand_lookalike");
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

describe("G2 brand_lookalike — fuzzy registrable-domain near-miss of a known brand", () => {
  it("transposition: gogole.com flags as a google lookalike + names brand/distance", () => {
    expect(codes("https://gogole.com")).toContain("brand_lookalike");
    const d = lookalikeDetail("https://gogole.com");
    expect(d).toContain("gogole.com");
    expect(d).toContain("google.com");
    expect(d).toContain("edit-distance 1");
  });

  it("insertion on a long brand: microsoftt.com flags", () => {
    expect(codes("https://microsoftt.com")).toContain("brand_lookalike");
    expect(lookalikeDetail("https://microsoftt.com")).toContain("microsoft.com");
  });

  it("TLD swap: paypal.co flags (distance 1 in the suffix)", () => {
    expect(codes("https://paypal.co")).toContain("brand_lookalike");
    expect(lookalikeDetail("https://paypal.co")).toContain("paypal.com");
  });

  it("distance-2 long brand: mecrosfot.com flags as a microsoft lookalike", () => {
    // A pure-letter typo (substitution + transposition), NOT a digit fold, so it
    // takes the fuzzy path: distance 2 against microsoft.com, label len 9 ≥ 8.
    expect(codes("https://mecrosfot.com")).toContain("brand_lookalike");
    const d = lookalikeDetail("https://mecrosfot.com");
    expect(d).toContain("microsoft.com");
    expect(d).toContain("edit-distance 2");
  });

  it("carries the lookalike weight (0.4)", () => {
    const reason = inspect("https://gogole.com").reasons.find(
      (x) => x.code === "brand_lookalike",
    )!;
    expect(reason.weight).toBeCloseTo(0.4, 5);
  });
});

describe("G2 — exact-brand negatives (the real brand never fires either code)", () => {
  const exact = [
    "https://paypal.com/login",
    "https://www.google.com/",
    "https://mail.google.com/", // registrable is google.com (exact)
    "https://github.com/anthropics/repo",
    "https://microsoft.com/",
  ];
  for (const input of exact) {
    it(`no brand code for the real brand ${JSON.stringify(input)}`, () => {
      const found = codes(input);
      expect(found).not.toContain("brand_lookalike");
      expect(found).not.toContain("brand_homoglyph");
    });
  }
});

describe("G2 brand_lookalike — short-domain false-positive guard", () => {
  // Distance-1 neighbours of SHORT brand labels are real, unrelated domains.
  const benign = [
    "https://vista.com/", // distance 1 from visa.com (label 'visa' < 5)
    "https://usp.com/", // transposition of ups.com (label 'ups' < 5)
    "https://wise.io/", // distance 1 (TLD) from wise.com (label 'wise' < 5)
    "https://uber.org/", // distance 1 (TLD) from uber.com (label 'uber' < 5)
  ];
  for (const input of benign) {
    it(`no brand code for short-brand neighbour ${JSON.stringify(input)}`, () => {
      const found = codes(input);
      expect(found).not.toContain("brand_lookalike");
      expect(found).not.toContain("brand_homoglyph");
    });
  }
});

describe("G2 — non-host negatives", () => {
  it("does not fire on an IP host", () => {
    expect(codes("http://127.0.0.1/")).not.toContain("brand_lookalike");
    expect(codes("http://127.0.0.1/")).not.toContain("brand_homoglyph");
    expect(codes("http://2130706433/")).not.toContain("brand_lookalike");
  });

  it("does not fire on empty / unparseable input (no registrable domain)", () => {
    expect(codes("")).not.toContain("brand_lookalike");
    expect(codes("   ")).not.toContain("brand_homoglyph");
  });

  it("does not fire on an unrelated, distant domain", () => {
    expect(codes("https://example.com/")).not.toContain("brand_lookalike");
    expect(codes("https://example.com/")).not.toContain("brand_homoglyph");
  });
});
