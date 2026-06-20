import { describe, expect, it } from "vitest";
import {
  ASCII_DIGIT_HOMOGLYPHS,
  foldAsciiDigitHomoglyphs,
} from "../src/data/ascii-confusables.js";

describe("ASCII_DIGIT_HOMOGLYPHS — the shared letter-shaped-digit map", () => {
  it("maps exactly 0->o, 1->l, 5->s and nothing else", () => {
    expect(ASCII_DIGIT_HOMOGLYPHS).toEqual({ "0": "o", "1": "l", "5": "s" });
  });

  it("does NOT map the ambiguous digits 2/3/4/6/7/8/9", () => {
    for (const d of ["2", "3", "4", "6", "7", "8", "9"]) {
      expect(ASCII_DIGIT_HOMOGLYPHS[d]).toBeUndefined();
    }
  });
});

describe("foldAsciiDigitHomoglyphs — replace letter-shaped digits", () => {
  it("folds the three mapped digits to letters", () => {
    expect(foldAsciiDigitHomoglyphs("g00gle")).toBe("google");
    expect(foldAsciiDigitHomoglyphs("paypa1")).toBe("paypal");
    expect(foldAsciiDigitHomoglyphs("mas5")).toBe("mass");
  });

  it("leaves unmapped digits untouched (only 0/1/5 fold)", () => {
    expect(foldAsciiDigitHomoglyphs("bet365")).toBe("bet36s"); // 5->s, 3/6 kept
    expect(foldAsciiDigitHomoglyphs("route53")).toBe("routes3"); // 5->s, 3 kept
    expect(foldAsciiDigitHomoglyphs("s3")).toBe("s3"); // 3 not a letter-shape
  });

  it("leaves non-digit characters (letters, dots) untouched", () => {
    expect(foldAsciiDigitHomoglyphs("paypal.com")).toBe("paypal.com");
    expect(foldAsciiDigitHomoglyphs("")).toBe("");
  });
});
