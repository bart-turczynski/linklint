import { describe, expect, it } from "vitest";
import { BRAND_DOMAINS, BRAND_WATCHLIST } from "../src/index.js";

// A registrable-domain shape: one or more lowercase labels + a TLD label.
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

describe("G1 brand watchlist — shape & invariants", () => {
  it("has a curated size in the ~50–200 range", () => {
    expect(BRAND_WATCHLIST.length).toBeGreaterThanOrEqual(50);
    expect(BRAND_WATCHLIST.length).toBeLessThanOrEqual(200);
  });

  it("every entry is well-formed (lowercase domain, valid registrable shape)", () => {
    for (const entry of BRAND_WATCHLIST) {
      expect(entry.domain).toBe(entry.domain.toLowerCase());
      expect(entry.domain).not.toMatch(/[\s/:]/);
      expect(entry.domain).toMatch(DOMAIN_RE);
      expect(entry.domain).toContain(".");
    }
  });

  it("domains are unique", () => {
    const domains = BRAND_WATCHLIST.map((b) => b.domain);
    expect(new Set(domains).size).toBe(domains.length);
  });
});

describe("G1 BRAND_DOMAINS — domain accessor (for G2)", () => {
  it("returns the deduped set of watchlist domains", () => {
    const expected = new Set(BRAND_WATCHLIST.map((b) => b.domain));
    expect(new Set(BRAND_DOMAINS)).toEqual(expected);
    expect(BRAND_DOMAINS.length).toBe(expected.size);
  });

  it("includes well-known registrable brand domains", () => {
    for (const d of ["paypal.com", "google.com", "microsoft.com", "apple.com"]) {
      expect(BRAND_DOMAINS).toContain(d);
    }
  });

  it("is all lowercase, valid-looking domains", () => {
    for (const d of BRAND_DOMAINS) {
      expect(d).toBe(d.toLowerCase());
      expect(d).toMatch(DOMAIN_RE);
    }
  });
});
