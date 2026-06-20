import { describe, expect, it } from "vitest";
import { skeleton } from "../src/index.js";

/** Build a string from explicit codepoints (keeps homograph fixtures readable). */
const cp = (...cps: number[]): string => String.fromCodePoint(...cps);

// Cyrillic homoglyphs of Latin letters (UTS#39 confusables, all single-script).
const CYR = {
  a: 0x0430, // а
  c: 0x0441, // с
  e: 0x0435, // е
  h: 0x04bb, // һ
  o: 0x043e, // о
  p: 0x0440, // р
  s: 0x0455, // ѕ
  y: 0x0443, // у
} as const;

describe("UTS#39 skeleton()", () => {
  it("is the identity on a plain ASCII string (already a skeleton)", () => {
    expect(skeleton("paypal.com")).toBe("paypal.com");
    expect(skeleton("chase.com")).toBe("chase.com");
    expect(skeleton("")).toBe("");
  });

  it("maps a Cyrillic homoglyph to its Latin prototype", () => {
    // а (U+0430 CYRILLIC SMALL LETTER A) → a (U+0061).
    expect(skeleton(cp(CYR.a))).toBe("a");
    // р (U+0440 CYRILLIC SMALL LETTER ER) → p (U+0070).
    expect(skeleton(cp(CYR.p))).toBe("p");
  });

  it("collapses an all-Cyrillic look-alike to the ASCII brand skeleton", () => {
    // сһаѕе → chase  (every letter a Cyrillic homoglyph)
    const cyrChase = cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e);
    expect(skeleton(cyrChase)).toBe("chase");
    expect(skeleton(`${cyrChase}.com`)).toBe("chase.com");
  });

  it("makes two visually-confusable strings skeleton-equal (the UTS#39 contract)", () => {
    const cyrYahoo = cp(CYR.y, CYR.a, CYR.h, CYR.o, CYR.o) + ".com";
    expect(skeleton(cyrYahoo)).toBe(skeleton("yahoo.com"));
  });

  it("does NOT collapse a non-brand Cyrillic word onto a brand", () => {
    // пример (Cyrillic 'example') is not confusable with any Latin brand.
    const primer = cp(0x043f, 0x0440, 0x0438, 0x043c, 0x0435, 0x0440);
    expect(skeleton(primer)).not.toBe("example");
    // It does still skeletonize deterministically (idempotent on its own output).
    expect(skeleton(skeleton(primer))).toBe(skeleton(primer));
  });

  it("is idempotent — skeleton(skeleton(x)) === skeleton(x)", () => {
    const cyrChase = cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e) + ".com";
    const once = skeleton(cyrChase);
    expect(skeleton(once)).toBe(once);
  });

  it("NFD-normalizes (a precomposed accent decomposes the same as its NFD form)", () => {
    const precomposed = "café"; // é = U+00E9
    const decomposed = "cafe" + cp(0x0301); // e + combining acute
    expect(skeleton(precomposed)).toBe(skeleton(decomposed));
  });

  it("never throws and stays synchronous on adversarial input", () => {
    expect(() => skeleton(cp(0x202e) + "evil" + cp(0x200b))).not.toThrow();
  });
});
