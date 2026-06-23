import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string, opts?: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.map((r) => r.code);

describe("idn_host — IDNs blocked by default (idnPolicy 'block')", () => {
  it("flags a genuine Unicode IDN at high by default", () => {
    const r = inspect("https://münchen.de");
    expect(r.reasons.map((x) => x.code)).toContain("idn_host");
    expect(r.severity).toBe("high");
    const reason = r.reasons.find((x) => x.code === "idn_host")!;
    expect(reason.weight).toBeCloseTo(0.7, 5);
  });

  it("flags the punycode (ACE) presentation identically", () => {
    // xn--mnchen-3ya.de === münchen.de
    expect(codes("https://xn--mnchen-3ya.de/")).toContain("idn_host");
    expect(inspect("https://xn--mnchen-3ya.de/").severity).toBe("high");
  });

  it("flags non-Latin scripts (Cyrillic, CJK, Greek)", () => {
    for (const url of ["https://пример.com", "https://日本語.jp", "https://Σίσυφος.gr"]) {
      expect(codes(url), url).toContain("idn_host");
    }
  });

  it("does NOT flag a pure-ASCII host", () => {
    expect(codes("https://example.com")).not.toContain("idn_host");
    expect(inspect("https://example.com").score).toBe(0);
  });

  it("does NOT flag an ASCII host with only a Unicode PATH (scoped to the registrable domain)", () => {
    const r = inspect(`https://example.com/p${String.fromCodePoint(0x0430)}y`);
    expect(r.reasons.map((x) => x.code)).not.toContain("idn_host");
    expect(r.score).toBe(0);
  });

  it("does NOT fire on IP hosts", () => {
    expect(codes("http://127.0.0.1/")).not.toContain("idn_host");
  });

  it("leaves malformed punycode to punycode_malformed (no double-flag)", () => {
    const c = codes("https://xn--abc.com/");
    expect(c).toContain("punycode_malformed");
    expect(c).not.toContain("idn_host");
    expect(inspect("https://xn--abc.com/").severity).toBe("low");
  });

  it("stacks on a dangerous IDN — the homograph blocker keeps it critical", () => {
    const cyr = (...cps: number[]) => String.fromCodePoint(...cps);
    const chase = `https://${cyr(0x0441, 0x04bb, 0x0430, 0x0455, 0x0435)}.com`; // сһаѕе.com
    const c = codes(chase);
    expect(c).toContain("idn_host");
    expect(c).toContain("homograph_latin_skeleton");
    expect(inspect(chase).severity).toBe("critical"); // blocker dominates
  });
});

describe("idn_host — overrides", () => {
  it("idnPolicy 'allow' suppresses the signal entirely (historical verdict)", () => {
    const r = inspect("https://münchen.de", { idnPolicy: "allow" });
    expect(r.reasons.map((x) => x.code)).not.toContain("idn_host");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("idnAllowlist exempts a specific registrable domain under 'block'", () => {
    const r = inspect("https://münchen.de", { idnAllowlist: ["münchen.de"] });
    expect(r.reasons.map((x) => x.code)).not.toContain("idn_host");
    expect(r.score).toBe(0);
    // a different IDN is still blocked
    expect(codes("https://köln.de", { idnAllowlist: ["münchen.de"] })).toContain("idn_host");
  });

  it("idnAllowlist matches across Unicode and punycode presentations", () => {
    // allow-list entry in Unicode exempts the punycode input, and vice-versa
    expect(codes("https://xn--mnchen-3ya.de/", { idnAllowlist: ["münchen.de"] })).not.toContain(
      "idn_host",
    );
    expect(codes("https://münchen.de", { idnAllowlist: ["xn--mnchen-3ya.de"] })).not.toContain(
      "idn_host",
    );
  });

  it("a subdomain is covered when its registrable domain is allow-listed", () => {
    expect(codes("https://shop.münchen.de", { idnAllowlist: ["münchen.de"] })).not.toContain(
      "idn_host",
    );
  });
});
