import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "ascii_homoglyph")?.detail ?? "";

describe("J4 ascii_homoglyph — same-script digit look-alikes", () => {
  it("g00gle (zeros for o) flags and reads as 'google'", () => {
    expect(codes("https://g00gle.com")).toContain("ascii_homoglyph");
    expect(detail("https://g00gle.com")).toContain("google");
  });

  it("paypa1 (one for l) flags and reads as 'paypal'", () => {
    expect(codes("https://paypa1.com")).toContain("ascii_homoglyph");
    expect(detail("https://paypa1.com")).toContain("paypal");
  });

  it("micr0soft flags", () => {
    expect(codes("https://micr0soft.com")).toContain("ascii_homoglyph");
  });

  it("catches a homoglyph label in the subdomain too", () => {
    expect(codes("https://amaz0n.evil.com")).toContain("ascii_homoglyph");
  });

  it("the cross-script detectors do NOT fire on a pure-ASCII homoglyph", () => {
    const found = codes("https://g00gle.com");
    expect(found).not.toContain("mixed_script");
    expect(found).not.toContain("confusable_char");
  });

  it("is low-weight on its own (0.2) — meaningful only in combination", () => {
    const r = inspect("https://g00gle.com");
    expect(r.severity).toBe("low");
    expect(r.score).toBeCloseTo(0.2, 5);
  });
});

describe("J4 ascii_homoglyph — must not over-flag legitimate digit domains (SC-2)", () => {
  const benign = [
    "https://s3.amazonaws.com", // short + 3 is not a letter-shaped digit
    "https://web3.example.com",
    "https://mp3.com",
    "https://bet365.com", // 3 and 6 disqualify the label
    "https://level3.net",
    "https://blink182.com", // 8 disqualifies
    "https://route53.aws",
    "https://i18n.example.com", // 8 disqualifies
    "https://1password.com", // leading digit reads as an obvious number
    "https://0day.today", // leading digit
    "https://o2.co.uk", // too short, 2 not a homoglyph
    "https://3m.com",
    "https://example.com",
    "https://github.com/anthropics/claude-code",
  ];
  for (const input of benign) {
    it(`no ascii_homoglyph for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("ascii_homoglyph");
    });
  }

  it("an IP host is never treated as a homoglyph word", () => {
    expect(codes("http://10.0.0.1/")).not.toContain("ascii_homoglyph");
    expect(codes("http://2130706433/")).not.toContain("ascii_homoglyph");
  });

  it("a mostly-numeric label (code, not a word) does not flag", () => {
    expect(codes("https://10101.com")).not.toContain("ascii_homoglyph");
  });
});
