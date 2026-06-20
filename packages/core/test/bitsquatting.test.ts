import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_bitsquat")?.detail ?? "";

describe("T3 brand_bitsquat — single-bit-flip neighbor of a watchlist brand", () => {
  // Auditable bit-flips (verify by hand):
  //   netfliz <- netflix : byte 'x'=0x78 (0b01111000), flip bit 1 (XOR 0x02) -> 'z'=0x7a (0b01111010)
  //   amazgn  <- amazon  : byte 'o'=0x6f (0b01101111), flip bit 3 (XOR 0x08) -> 'g'=0x67 (0b01100111)
  it("netfliz.com is a single-bit-flip of netflix (x->z, bit 1)", () => {
    expect(codes("https://netfliz.com")).toContain("brand_bitsquat");
    expect(detail("https://netfliz.com")).toContain("netflix");
  });

  it("amazgn.com is a single-bit-flip of amazon (o->g, bit 3)", () => {
    expect(codes("https://amazgn.com")).toContain("brand_bitsquat");
    expect(detail("https://amazgn.com")).toContain("amazon");
  });

  it("scores in the LOW band on its own (weight 0.15)", () => {
    // Inspect the bitsquat reason's attached weight directly — a single bit flip
    // is also edit-distance 1, so brand_lookalike stacks and lifts the aggregate
    // severity; the unit under test is the 0.15 weight on OUR code.
    const result = inspect("https://netfliz.com");
    const reason = result.reasons.find((r) => r.code === "brand_bitsquat")!;
    expect(reason.weight).toBeCloseTo(0.15, 5);
  });
});

describe("T3 — SC-2 precision negatives (must never fire)", () => {
  const benign = [
    // exact brand domains — they ARE the brand
    "https://netflix.com",
    "https://amazon.com",
    "https://paypal.com",
    "https://google.com",
    // a 2-bit-away label must NOT fire (only single-bit neighbors do):
    //   netfly <- netflix needs an x->y flip (bit 0) AND a deletion-equivalent;
    //   use a verified 2-bit case: 'nf_'... instead probe a clear 2-flip label.
    //   'oetfliz' = netflix with TWO byte changes (n->o bit0, x->z bit1) — 2-bit-away.
    "https://oetfliz.com",
    // legit unrelated words / sites
    "https://example.com",
    "https://github.com/anthropics/claude-code",
    "https://secure-account-verify-login.com",
    "https://accounts.google.com",
    // short-brand collisions the length guard must protect
    "https://ups.com",
    "https://dhl.com",
    "https://ibm.com",
    "https://n26.com",
    "https://dpd.com",
    "https://box.com",
    "https://meta.com",
    "https://visa.com",
    "https://x.com",
    // non-ASCII / IP / unparseable
    "https://пример.com",
    "http://127.0.0.1/",
    "",
  ];
  for (const input of benign) {
    it(`no bitsquat for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("brand_bitsquat");
    });
  }
});
