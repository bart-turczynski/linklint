import { describe, expect, it } from "vitest";
import { analyzeHost, looksLikeRegistrableDomain } from "../src/parse/psl.js";

describe("analyzeHost — eTLD+1 extraction", () => {
  it("plain .com", () => {
    const r = analyzeHost("www.example.com");
    expect(r.registrableDomain).toBe("example.com");
    expect(r.publicSuffix).toBe("com");
    expect(r.subdomain).toBe("www");
  });

  it("multi-level ICANN suffix (co.uk)", () => {
    const r = analyzeHost("foo.bar.co.uk");
    expect(r.registrableDomain).toBe("bar.co.uk");
    expect(r.publicSuffix).toBe("co.uk");
  });

  it("private suffix treated as registrable under ICANN-only rules (github.io)", () => {
    const r = analyzeHost("user.github.io");
    expect(r.registrableDomain).toBe("github.io");
  });

  it("unknown TLD falls back to the implicit '*' rule (eTLD+1 = label.tld)", () => {
    const r = analyzeHost("foo.invalidtldxyz");
    expect(r.registrableDomain).toBe("foo.invalidtldxyz");
    expect(r.publicSuffix).toBe("invalidtldxyz");
  });

  it("a single bare label has no registrable domain", () => {
    expect(analyzeHost("localhost").registrableDomain).toBeNull();
  });

  it("detects IPs", () => {
    expect(analyzeHost("127.0.0.1").isIp).toBe(true);
    expect(analyzeHost("example.com").isIp).toBe(false);
  });
});

describe("looksLikeRegistrableDomain", () => {
  it("true for an exact eTLD+1", () => {
    expect(looksLikeRegistrableDomain("paypal.com")).toBe(true);
  });
  it("false for a subdomain'd host", () => {
    expect(looksLikeRegistrableDomain("www.paypal.com")).toBe(false);
  });
  it("false for a bare suffix", () => {
    expect(looksLikeRegistrableDomain("co.uk")).toBe(false);
  });
});
