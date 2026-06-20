import { describe, expect, it } from "vitest";
import { BRAND_DOMAINS, BRAND_KEYWORDS, BRAND_WATCHLIST } from "../src/index.js";
import { isBrandKeyword } from "../src/data/brands.js";

// A registrable-domain shape: one or more lowercase labels + a TLD label.
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

describe("G1 brand watchlist — shape & invariants", () => {
  it("has a curated size in the ~50–200 range", () => {
    expect(BRAND_WATCHLIST.length).toBeGreaterThanOrEqual(50);
    expect(BRAND_WATCHLIST.length).toBeLessThanOrEqual(200);
  });

  it("every entry is well-formed (lowercase domain, valid-looking, keywords lowercase)", () => {
    for (const entry of BRAND_WATCHLIST) {
      // domain: lowercase, no scheme/path/whitespace, valid registrable shape
      expect(entry.domain).toBe(entry.domain.toLowerCase());
      expect(entry.domain).not.toMatch(/[\s/:]/);
      expect(entry.domain).toMatch(DOMAIN_RE);
      expect(entry.domain).toContain(".");

      // keywords: an array of lowercase, non-empty, separator-free tokens
      expect(Array.isArray(entry.keywords)).toBe(true);
      for (const kw of entry.keywords) {
        expect(kw.length).toBeGreaterThan(0);
        expect(kw).toBe(kw.toLowerCase());
        expect(kw).toMatch(/^[a-z0-9]+$/);
      }
    }
  });

  it("domains are unique", () => {
    const domains = BRAND_WATCHLIST.map((b) => b.domain);
    expect(new Set(domains).size).toBe(domains.length);
  });

  it("at least one entry carries keywords (the list is not domain-only)", () => {
    expect(BRAND_WATCHLIST.some((b) => b.keywords.length > 0)).toBe(true);
  });
});

describe("G1 BRAND_KEYWORDS — derived contract", () => {
  it("is exactly the union of all watchlist keywords", () => {
    const union = new Set(BRAND_WATCHLIST.flatMap((b) => b.keywords));
    expect(new Set(BRAND_KEYWORDS)).toEqual(union);
    expect(BRAND_KEYWORDS.size).toBe(union.size);
  });

  it("still recognizes seed brands (back-compat with J7)", () => {
    for (const seed of ["paypal", "google", "gmail", "microsoft", "amazon", "fedex", "ups"]) {
      expect(BRAND_KEYWORDS.has(seed)).toBe(true);
    }
  });
});

describe("G1 isBrandKeyword — case-insensitive", () => {
  it("recognizes seed brands regardless of case", () => {
    expect(isBrandKeyword("paypal")).toBe(true);
    expect(isBrandKeyword("PayPal")).toBe(true);
    expect(isBrandKeyword("GOOGLE")).toBe(true);
    expect(isBrandKeyword("Microsoft")).toBe(true);
  });

  it("rejects non-brand tokens", () => {
    expect(isBrandKeyword("notabrand")).toBe(false);
    expect(isBrandKeyword("")).toBe(false);
  });

  it("agrees with BRAND_KEYWORDS membership", () => {
    for (const kw of BRAND_KEYWORDS) {
      expect(isBrandKeyword(kw)).toBe(true);
      expect(isBrandKeyword(kw.toUpperCase())).toBe(true);
    }
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
