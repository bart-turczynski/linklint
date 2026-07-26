import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { toAscii } from "../src/unicode/idna.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "homograph_skeleton_collision")?.detail ?? "";

/** Build a host from explicit codepoints — keeps Unicode fixtures readable. */
const cp = (...cps: number[]): string => String.fromCodePoint(...cps);

// Cyrillic homoglyphs of Latin letters (single-script — no script mixing).
const CYR = {
  a: 0x0430,
  c: 0x0441,
  e: 0x0435,
  h: 0x04bb,
  i: 0x0456,
  d: 0x0501,
  o: 0x043e,
  p: 0x0440,
  s: 0x0455,
  x: 0x0445,
  y: 0x0443,
} as const;

// сһаѕе.com — an all-Cyrillic whole-label look-alike of chase.com.
const CYR_CHASE = `https://${cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e)}.com`;
// уаһоо.com — all-Cyrillic yahoo.com.
const CYR_YAHOO = `https://${cp(CYR.y, CYR.a, CYR.h, CYR.o, CYR.o)}.com`;
// ехреԁіа.com — all-Cyrillic expedia.com.
const CYR_EXPEDIA = `https://${cp(CYR.e, CYR.x, CYR.p, CYR.e, CYR.d, CYR.i, CYR.a)}.com`;

describe("E3 homograph_skeleton_collision — single-script whole-label homograph of a brand", () => {
  it("an all-Cyrillic сһаѕе.com collides with the chase.com skeleton", () => {
    expect(codes(CYR_CHASE)).toContain("homograph_skeleton_collision");
    const d = detail(CYR_CHASE);
    expect(d).toContain("chase.com"); // names the brand
  });

  it("an all-Cyrillic уаһоо.com collides with yahoo.com", () => {
    expect(codes(CYR_YAHOO)).toContain("homograph_skeleton_collision");
    expect(detail(CYR_YAHOO)).toContain("yahoo.com");
  });

  it("an all-Cyrillic ехреԁіа.com collides with expedia.com", () => {
    expect(codes(CYR_EXPEDIA)).toContain("homograph_skeleton_collision");
    expect(detail(CYR_EXPEDIA)).toContain("expedia.com");
  });

  // Regression: LINK-iyseozhh. The detector read the registrable domain as
  // written, so the punycode spelling of these same hosts skipped the brand
  // attribution entirely.
  describe("punycode parity — the ACE spelling attributes the same brand", () => {
    for (const [url, brand] of [
      [CYR_CHASE, "chase.com"],
      [CYR_YAHOO, "yahoo.com"],
      [CYR_EXPEDIA, "expedia.com"],
    ] as const) {
      it(`attributes ${brand} from the punycode form too`, () => {
        const ace = `https://${toAscii(new URL(url).hostname)}`;
        expect(ace).toContain("xn--");
        expect(codes(ace)).toContain("homograph_skeleton_collision");
        expect(detail(ace)).toContain(brand);
        expect(inspect(ace).score).toBe(inspect(url).score);
      });
    }
  });

  it("scores at the decisive brand-impersonation weight (0.5)", () => {
    const reason = inspect(CYR_CHASE).reasons.find(
      (x) => x.code === "homograph_skeleton_collision",
    )!;
    expect(reason.weight).toBeCloseTo(0.5, 5);
  });

  it("a single-script homograph does NOT fire mixed_script (the gap it fills)", () => {
    // The whole point of E3: no script mixing, so mixed_script is silent — this
    // detector is the only thing that catches the homograph.
    expect(codes(CYR_CHASE)).not.toContain("mixed_script");
  });
});

describe("E3 — no double-fire with G2 brand_homoglyph (mutually exclusive)", () => {
  it("a pure-ASCII digit fold stays brand_homoglyph, never skeleton_collision", () => {
    expect(codes("https://paypa1.com")).toContain("brand_homoglyph");
    expect(codes("https://paypa1.com")).not.toContain("homograph_skeleton_collision");
    expect(codes("https://g00gle.com")).toContain("brand_homoglyph");
    expect(codes("https://g00gle.com")).not.toContain("homograph_skeleton_collision");
  });

  it("a non-ASCII homograph stays skeleton_collision, never brand_homoglyph", () => {
    expect(codes(CYR_CHASE)).not.toContain("brand_homoglyph");
  });
});

describe("E3 — SC-2 precision negatives (must never fire)", () => {
  const benign = [
    "https://chase.com", // the real brand (ASCII — guarded out)
    "https://paypal.com",
    "https://www.yahoo.com/",
    // legitimate single-script IDNs that are NOT brand look-alikes
    "https://пexample.com".replace("п", cp(0x043f)), // Cyrillic 'пример'-ish, not a brand
    `https://${cp(0x043f, 0x0440, 0x0438, 0x043c, 0x0435, 0x0440)}.com`, // пример.com
    "https://straße.de", // German ß IDN
    "https://münchen.de", // German ü IDN
    "http://127.0.0.1/", // IP host
    "", // unparseable
  ];
  for (const input of benign) {
    it(`no skeleton-collision for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("homograph_skeleton_collision");
    });
  }
});
