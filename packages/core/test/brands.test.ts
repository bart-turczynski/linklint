import { describe, expect, it } from "vitest";
import { BRAND_DOMAINS, BRAND_WATCHLIST } from "../src/index.js";
import { analyzeHost } from "../src/parse/psl.js";

// A registrable-domain shape: one or more lowercase labels + a TLD label.
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/**
 * Watchlist entries that are deliberately NOT registrable domains (LINK-scktwvio).
 *
 * `turbotax.intuit.com` has registrable domain `intuit.com`, so the domain-tier
 * detectors — which key on `ctx.registrableDomain` — can never fire for it; it is
 * pinned as INERT in `brand-fold-surface.test.ts`. It is retained anyway because
 * `significantLabel()` yields `turbotax`, which makes it a member of
 * `BRAND_LABEL_SET` and so carries real weight in the label tier.
 *
 * Note `barclays.co.uk` is NOT an exception: `co.uk` is a public suffix, so that
 * entry genuinely is a registrable domain.
 */
const MULTI_LABEL_BRANDS: ReadonlySet<string> = new Set(["turbotax.intuit.com"]);

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

  it("every entry equals its own registrable domain (except documented multi-label entries)", () => {
    for (const entry of BRAND_WATCHLIST) {
      const registrable = analyzeHost(entry.domain).registrableDomain;
      if (MULTI_LABEL_BRANDS.has(entry.domain)) {
        // Documented exception: must genuinely NOT be its own registrable domain,
        // otherwise it does not belong in the exception set.
        expect(registrable).not.toBe(entry.domain);
        continue;
      }
      expect(registrable).toBe(entry.domain);
    }
  });

  it("the multi-label exception set is exactly the documented one", () => {
    expect([...MULTI_LABEL_BRANDS]).toEqual(["turbotax.intuit.com"]);
    expect(BRAND_DOMAINS).toContain("turbotax.intuit.com");
    // barclays.co.uk is a registrable domain and needs no exception.
    expect(analyzeHost("barclays.co.uk").registrableDomain).toBe("barclays.co.uk");
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
