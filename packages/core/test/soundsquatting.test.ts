import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_soundsquat")?.detail ?? "";

describe("T2 brand_soundsquat — phonetic homophone of a watchlist brand", () => {
  it("netflicks.com is a homophone of netflix (ck->k, x->ks)", () => {
    expect(codes("https://netflicks.com")).toContain("brand_soundsquat");
    expect(detail("https://netflicks.com")).toContain("netflix");
  });

  it("dropboks.com is a homophone of dropbox (x->ks)", () => {
    expect(codes("https://dropboks.com")).toContain("brand_soundsquat");
    expect(detail("https://dropboks.com")).toContain("dropbox");
  });

  it("spotifi.com is a homophone of spotify (y->i)", () => {
    expect(codes("https://spotifi.com")).toContain("brand_soundsquat");
    expect(detail("https://spotifi.com")).toContain("spotify");
  });

  it("shopifi.com is a homophone of shopify", () => {
    expect(codes("https://shopifi.com")).toContain("brand_soundsquat");
    expect(detail("https://shopifi.com")).toContain("shopify");
  });

  it("koinbase.com is a homophone of coinbase (c->k)", () => {
    expect(codes("https://koinbase.com")).toContain("brand_soundsquat");
    expect(detail("https://koinbase.com")).toContain("coinbase");
  });

  it("netflicks.com / dropboks.com are INVISIBLE to the edit-distance siblings", () => {
    // The whole point of T2: these slip past brand_lookalike / brand_homoglyph,
    // so brand_soundsquat is the only thing that catches them.
    expect(codes("https://netflicks.com")).not.toContain("brand_lookalike");
    expect(codes("https://netflicks.com")).not.toContain("brand_homoglyph");
    expect(codes("https://dropboks.com")).not.toContain("brand_lookalike");
    expect(codes("https://dropboks.com")).not.toContain("brand_homoglyph");
  });

  it("scores in the medium band on its own (weight 0.3)", () => {
    const result = inspect("https://netflicks.com");
    const reason = result.reasons.find((r) => r.code === "brand_soundsquat")!;
    expect(reason.weight).toBeCloseTo(0.3, 5);
    expect(result.severity).toBe("medium");
  });
});

describe("T2 — SC-2 precision negatives (must never fire)", () => {
  const benign = [
    // exact brand domains — they ARE the brand
    "https://netflix.com",
    "https://dropbox.com",
    "https://spotify.com",
    "https://paypal.com",
    "https://coinbase.com",
    // legit unrelated words / sites
    "https://example.com",
    "https://github.com/anthropics/claude-code",
    "https://secure-account-verify-login.com",
    "https://accounts.google.com",
    "https://amazonaws.com",
    // short-brand collisions the length guard must protect
    "https://ups.com",
    "https://dhl.com",
    "https://ibm.com",
    "https://n26.com",
    "https://hsbc.com",
    "https://dpd.com",
    "https://wise.com",
    "https://box.com",
    "https://meta.com",
    "https://visa.com",
    "https://cash.app",
    "https://x.com",
    // non-ASCII / IP / unparseable
    "https://пример.com",
    "http://127.0.0.1/",
    "",
  ];
  for (const input of benign) {
    it(`no soundsquat for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("brand_soundsquat");
    });
  }
});
