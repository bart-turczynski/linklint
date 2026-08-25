import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * FR-D-8 scope pins (LINK-pbilvjuv).
 *
 * `embedded_domain_in_subdomain` scans every contiguous window of subdomain
 * labels and fires on any window that is itself a well-formed registrable
 * domain. This file pins the two halves of that scope separately:
 *
 *  1. the attack shapes that MUST keep firing, and
 *  2. the ordinary regional-subdomain convention (`www.eu.playstation.com`),
 *     which currently fires because `www.eu` genuinely IS an eTLD+1.
 *
 * Block 2 is pinned to the CURRENT (buggy) behavior in this commit so the
 * following commit's inversion is a visible behavior change, not a new test
 * arriving green.
 */

const fired = (url: string): boolean =>
  inspect(url).reasons.some((r) => r.code === "embedded_domain_in_subdomain");

const embeddedDetail = (url: string): string | undefined =>
  inspect(url).reasons.find((r) => r.code === "embedded_domain_in_subdomain")?.detail;

// ── 1. Attack shapes that must keep firing ──────────────────────────────────
describe("embedded_domain_in_subdomain — genuine embedded registrable domains", () => {
  it.each([
    ["https://paypal.com.spoof.info/", "paypal.com", "spoof.info"],
    ["https://paypal.com.login.evil.com/", "paypal.com", "evil.com"],
    ["https://login.paypal.com.account.evil.com/", "paypal.com", "evil.com"],
    ["https://secure-paypal.com.cdn.evil.com/", "secure-paypal.com", "evil.com"],
    ["https://a.b.c.d.paypal.com.evil.tk/", "paypal.com", "evil.tk"],
    // Multi-label ccTLD suffix: `co.uk` is not a bare two-letter label, so the
    // region-code carve-out below must not reach it.
    ["https://paypal.co.uk.evil.com/", "paypal.co.uk", "evil.com"],
  ])("%s flags %s against the real domain %s", (url, window, real) => {
    const detail = embeddedDetail(url);
    expect(detail, url).toBeDefined();
    expect(detail, url).toContain(window);
    expect(detail, url).toContain(real);
  });

  it("stays at or above the medium band for the canonical case", () => {
    const r = inspect("https://paypal.com.spoof.info/");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });
});

// ── 2. Benign shapes that must never fire ───────────────────────────────────
describe("embedded_domain_in_subdomain — pre-existing benign guards", () => {
  it.each([
    // E4 hyphenated near-miss: `eu-west-1` is not a public suffix, which is
    // why the regional false positive below survived undetected.
    "https://cdn.assets.eu-west-1.example.com/",
    "https://cdn.assets.eu-west-1.svc.example.com/",
    "https://sub.domain.example.co.uk/a/b",
    "https://a.b.c.d.e.example.com/",
    "https://svc.uc.r.appspot.com/",
    "https://bucket.nyc3.digitaloceanspaces.com/",
    "https://www.zz.example.com/",
    "https://eu.playstation.com/",
  ])("%s stays clean", (url) => {
    expect(fired(url), url).toBe(false);
  });
});

// ── 3. LINK-pbilvjuv: the regional-subdomain false positive ─────────────────
// PINNED AS-IS. Every assertion in this block is inverted by the fix commit.
describe("LINK-pbilvjuv — regional subdomains currently misfire (pinned bug)", () => {
  it.each([
    "https://www.eu.playstation.com/",
    "https://api.eu.example.com/",
    "https://www.uk.example.com/",
    "https://www.de.example.com/",
    "https://cdn.www.eu.example.co.uk/",
  ])("%s fires embedded_domain_in_subdomain today", (url) => {
    expect(fired(url), url).toBe(true);
  });

  it("Sony's real EU storefront scores 0.50/medium", () => {
    const r = inspect("https://www.eu.playstation.com/");
    expect(r.score).toBeCloseTo(0.5, 5);
    expect(r.severity).toBe("medium");
  });

  it("a .exe path pushes the same benign host to the blocking band", () => {
    const r = inspect("https://www.eu.playstation.com/update.exe");
    expect(r.score).toBeCloseTo(0.75, 5);
    expect(r.severity).toBe("high");
  });
});
