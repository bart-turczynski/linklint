import { describe, expect, it } from "vitest";
import { inspect, WEIGHTS } from "../src/index.js";

/**
 * T2.14 (LINK-woxuwnks) — malformed percent-encoding.
 *
 * The finding is architecture §1.1 claim (a), form 3 (false self-description):
 * `%` declares "two hex digits follow" and they do not. It is priced at
 * `punycode_malformed`'s 0.2 because it is the same shape of claim — a false
 * self-description that every reader agrees is false.
 */

const reasons = (url: string) => inspect(url, { agentMode: true }).reasons.map((r) => r.code);
const scored = (url: string) => inspect(url, { agentMode: true });

describe("percent_encoding_malformed — fires on '%' without two hex digits", () => {
  it.each([
    ["https://example.com/a%zzb", "path, non-hex pair"],
    ["https://example.com/x%", "path, trailing '%' with nothing after it"],
    ["https://example.com/a%2gb", "path, one hex digit then a non-hex character"],
    ["https://ex%zzample.com/", "host"],
    ["https://example.com/?q=100%discount", "query"],
    ["https://example.com/#frag%", "fragment"],
  ])("%s (%s)", (url) => {
    expect(reasons(url)).toContain("percent_encoding_malformed");
  });

  it("fires in userinfo", () => {
    expect(reasons("https://us%zzer@example.com/")).toContain("percent_encoding_malformed");
  });

  it("names the offending token and the component in the detail", () => {
    const r = scored("https://example.com/a%zzb").reasons.find(
      (x) => x.code === "percent_encoding_malformed",
    );
    expect(r?.detail).toContain("%zz in path");
    expect(r?.detail).toContain("RFC 3986");
  });

  it("renders a trailing '%' as %<end> rather than a bare '%'", () => {
    const r = scored("https://example.com/x%").reasons.find(
      (x) => x.code === "percent_encoding_malformed",
    );
    expect(r?.detail).toContain("%<end> in path");
  });

  it("caps the detail at three tokens and counts the rest", () => {
    const r = scored("https://example.com/%z1/%z2/%z3/%z4/%z5").reasons.find(
      (x) => x.code === "percent_encoding_malformed",
    );
    expect(r?.detail).toContain("(+2 more)");
  });
});

describe("percent_encoding_malformed — does not fire on well-formed escapes", () => {
  it.each([
    "https://example.com/",
    "https://example.com/?q=hello%20world",
    "https://example.com/%E4%B8%AD", // parser-produced UTF-8, well-formed by construction
    "https://example.com/a%2fb", // encoded separator — encoding_obfuscation's job
    "https://example.com/a%25%32%66b", // double-encoded, still well-formed
    "https://example.com/a%C0%AFb", // overlong UTF-8 — well-formed triplets
    "https://example.com/%41%42%43",
  ])("%s", (url) => {
    expect(reasons(url)).not.toContain("percent_encoding_malformed");
  });

  it("leaves the encoding_obfuscation verdict untouched for well-formed input", () => {
    const r = scored("https://example.com/a%C0%AFb");
    expect(r.reasons.map((x) => x.code)).toEqual(["encoding_obfuscation"]);
    expect(r.score).toBeCloseTo(0.35, 5);
  });
});

describe("percent_encoding_malformed — weight and severity", () => {
  it("is priced at punycode_malformed's 0.2 (same claim shape, §1.1 form 3)", () => {
    expect(WEIGHTS.percent_encoding_malformed).toBe(0.2);
    expect(WEIGHTS.percent_encoding_malformed).toBe(WEIGHTS.punycode_malformed);
  });

  it("lands in the 'low' band on its own", () => {
    const r = scored("https://example.com/a%zzb");
    expect(r.severity).toBe("low");
    expect(r.score).toBeCloseTo(0.2, 5);
  });

  it("scores '%zz' and a lone '%' identically — the split the issue proposed tracked reader tolerance, not the claim", () => {
    const lonePercent = scored("https://example.com/100%discount").score ?? -1;
    expect(scored("https://example.com/a%zzb").score).toBeCloseTo(lonePercent, 5);
  });
});
