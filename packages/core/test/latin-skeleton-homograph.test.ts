import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const cp = (...cps: number[]): string => String.fromCodePoint(...cps);

// Cyrillic homoglyphs of Latin letters (single-script — no script mixing).
const CYR = { a: 0x0430, c: 0x0441, e: 0x0435, h: 0x04bb, i: 0x0456, d: 0x0501, o: 0x043e, p: 0x0440, s: 0x0455, x: 0x0445 } as const;

// сһаѕе.com — all-Cyrillic look-alike of the BRAND chase.com.
const CYR_CHASE = `https://${cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e)}.com`;
// ассеѕѕ.com — all-Cyrillic look-alike of the NON-brand word "access".
const CYR_ACCESS = `https://${cp(CYR.a, CYR.c, CYR.c, CYR.e, CYR.s, CYR.s)}.com`;

describe("homograph_latin_skeleton — target-less whole-label homograph (pure-ASCII skeleton)", () => {
  it("fires on a NON-brand all-Cyrillic host whose skeleton folds to pure Latin", () => {
    // The defining case: no brand watchlist match, yet the host masquerades as
    // the ASCII word 'access'. Only the target-less detector catches this.
    expect(codes(CYR_ACCESS)).toContain("homograph_latin_skeleton");
    expect(codes(CYR_ACCESS)).not.toContain("homograph_skeleton_collision");
  });

  it("is a BLOCKER (weight 1.0) and lands critical on its own", () => {
    const r = inspect(CYR_ACCESS);
    const reason = r.reasons.find((x) => x.code === "homograph_latin_skeleton")!;
    expect(reason.weight).toBe(1);
    expect(r.severity).toBe("critical");
  });

  it("stacks with homograph_skeleton_collision on a brand homograph", () => {
    const c = codes(CYR_CHASE);
    expect(c).toContain("homograph_latin_skeleton"); // blocks
    expect(c).toContain("homograph_skeleton_collision"); // adds brand attribution
    expect(inspect(CYR_CHASE).severity).toBe("critical");
  });

  it("a single-script homograph does NOT fire mixed_script", () => {
    expect(codes(CYR_ACCESS)).not.toContain("mixed_script");
  });
});

describe("homograph_latin_skeleton — precision negatives (genuine non-Latin retains a non-ASCII skeleton)", () => {
  const benign = [
    `https://${cp(0x043f, 0x0440, 0x0438, 0x043c, 0x0435, 0x0440)}.com`, // пример.com (RU 'example')
    `https://${cp(0x0440, 0x043e, 0x0441, 0x0441, 0x0438, 0x044f)}.com`, // россия.com (RU 'russia')
    "https://münchen.de", // German ü IDN
    "https://straße.de", // German ß IDN
    `https://${cp(0x65e5, 0x672c, 0x8a9e)}.jp`, // 日本語.jp
    "https://example.com", // pure ASCII — never a cross-script homograph
    "https://g00gle.com", // ASCII digit-fold belongs to ascii_homoglyph/brand_homoglyph
    "http://127.0.0.1/", // IP host
    "", // unparseable
  ];
  for (const input of benign) {
    it(`does not fire for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("homograph_latin_skeleton");
    });
  }

  it("does not fire on a fullwidth-Latin compatibility homograph (owned by idna_mapping_ambiguity)", () => {
    // ｇｏｏｇｌｅ.com — fullwidth Latin NFKC-folds to pure ASCII; excluded by the
    // post-NFKC non-ASCII guard so the two detectors don't overlap.
    const fullwidth = `https://${cp(0xff47, 0xff4f, 0xff4f, 0xff47, 0xff4c, 0xff45)}.com`;
    expect(codes(fullwidth)).not.toContain("homograph_latin_skeleton");
  });
});
