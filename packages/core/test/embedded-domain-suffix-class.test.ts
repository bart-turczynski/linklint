import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * FR-D-8 window-suffix scope pins (LINK-vuqdzmzy).
 *
 * `embedded_domain_in_subdomain` fires on any contiguous window of subdomain
 * labels that is itself a well-formed ICANN registrable domain. Which *suffix*
 * that window ends in was never part of the firing condition, so a window under
 * a post-2000 expansion gTLD (`console.cloud`, `www.tax`, `n.news`) is treated
 * exactly like one under `.com`.
 *
 * This file pins the CURRENT behaviour on both sides before it is narrowed, so
 * the narrowing shows up as an edit to an existing assertion rather than as a
 * new test arriving green. Blocks 1 and 3 are pinned to the behaviour that is
 * about to change and are inverted by the following commit; block 2 is pinned
 * to behaviour that must survive it.
 */

const embeddedDetail = (url: string): string | undefined =>
  inspect(url).reasons.find((r) => r.code === "embedded_domain_in_subdomain")?.detail;

const fired = (url: string): boolean => embeddedDetail(url) !== undefined;

// ── 1. Ordinary hosts that fire TODAY on an expansion-gTLD window ───────────
// Every hostname here is real and was drawn from the CrUX top-1M browsed-origins
// corpus by the LINK-kgiviycg measurement, not invented. Each scores
// 0.50/medium on this rule alone, and each 0.50 stacks under probabilistic-OR
// with any other finding on the same URL.
describe("LINK-vuqdzmzy — expansion-gTLD windows on ordinary hosts (pinned as-is)", () => {
  it.each([
    ["https://console.cloud.google.com/", "console.cloud"], // Google Cloud Console
    ["https://www.tax.service.gov.uk/", "www.tax"], // HMRC
    ["https://n.news.naver.com/", "n.news"], // Naver News
    ["https://in.search.yahoo.com/", "in.search"],
    ["https://m.place.naver.com/", "m.place"],
    ["https://m.cafe.daum.net/", "m.cafe"],
    ["https://a24.app.gree-pf.net/", "a24.app"],
    ["https://rof.x3.international.travian.com/", "x3.international"],
    ["https://api.dev.example.com/", "api.dev"],
  ])("%s fires on the window %s", (url, window) => {
    const detail = embeddedDetail(url);
    expect(detail, url).toBeDefined();
    expect(detail, url).toContain(window);
  });

  it("the Google Cloud Console scores 0.50/medium on this rule alone", () => {
    const r = inspect("https://console.cloud.google.com/");
    expect(r.reasons.map((x) => x.code)).toEqual(["embedded_domain_in_subdomain"]);
    expect(r.score).toBeCloseTo(0.5, 5);
    expect(r.severity).toBe("medium");
  });

  // Pre-2012 expansion and sponsored gTLDs are the same phenomenon: `.post`
  // (2011) and `.travel` (2005) predate the 2012 round entirely.
  it.each([
    ["https://www.post.japanpost.jp/", "www.post"], // Japan Post
    ["https://hotel.travel.rakuten.co.jp/", "hotel.travel"], // Rakuten Travel
    ["https://pro.store.yahoo.co.jp/", "pro.store"],
    ["https://www.jobs.example.com/", "www.jobs"],
    ["https://www.info.example.com/", "www.info"],
  ])("%s fires on the pre-2012 expansion window %s", (url, window) => {
    const detail = embeddedDetail(url);
    expect(detail, url).toBeDefined();
    expect(detail, url).toContain(window);
  });

  // A brand gTLD is an expansion gTLD too: `.amazon` was delegated in the 2012
  // round, so Amazon's real Belgian storefront fires on `www.amazon`.
  it("Amazon's real Belgian storefront fires on `www.amazon`", () => {
    expect(embeddedDetail("https://www.amazon.com.be/")).toContain("www.amazon");
  });

  // `in-addr.arpa` is a multi-label suffix under a legacy gTLD — reverse-DNS
  // naming, not an authority claim.
  it("a reverse-DNS window under in-addr.arpa fires", () => {
    expect(embeddedDetail("https://1.2.3.in-addr.arpa.evil.com/")).toContain("3.in-addr.arpa");
  });
});

// ── 2. The two classes that must keep firing ────────────────────────────────
// These are the attack shapes FR-D-8 exists to catch and no narrowing may
// touch them.
describe("LINK-vuqdzmzy — legacy-gTLD and multi-label-ccTLD windows keep firing", () => {
  it.each([
    ["https://paypal.com.spoof.info/", "paypal.com"],
    ["https://paypal.com.login.evil.com/", "paypal.com"],
    ["https://secure-paypal.com.cdn.evil.com/", "secure-paypal.com"],
    ["https://facebook.com.evil.tk/", "facebook.com"],
    ["https://hmrc.gov.evil.com/", "hmrc.gov"],
    ["https://paypal.co.uk.evil.com/", "paypal.co.uk"],
    ["https://amazon.co.jp.evil.com/", "amazon.co.jp"],
    ["https://halifax.co.uk.evil.com/", "halifax.co.uk"],
    ["https://anz.com.au.banking-auth.example/", "anz.com.au"],
  ])("%s still reports %s", (url, window) => {
    const detail = embeddedDetail(url);
    expect(detail, url).toBeDefined();
    expect(detail, url).toContain(window);
  });

  it("the canonical case stays at or above medium", () => {
    expect(["medium", "high", "critical"]).toContain(inspect("https://paypal.com.spoof.info/").severity);
  });

  it("the region-code carve-out is unchanged", () => {
    expect(fired("https://www.eu.playstation.com/")).toBe(false);
    expect(embeddedDetail("https://www.eu.paypal.com.evil.info/")).toContain("paypal.com");
  });
});

// ── 3. Which window wins when a brand gTLD sits left of the brand's .com ────
// `appleid.apple.com` is Apple's real Apple ID host. Hung off an attacker
// domain, its subdomain contains BOTH `appleid.apple` (a `.apple` window) and
// `apple.com` (a `.com` window). The scan runs longest-first and then
// left-to-right, so today the `.apple` window wins and `apple.com` is never
// reached.
describe("LINK-vuqdzmzy — brand-gTLD window shadows the legacy-gTLD window (pinned as-is)", () => {
  it.each([
    ["https://appleid.apple.com.evil.tk/", "appleid.apple"],
    ["https://accounts.google.com.evil.tk/", "accounts.google"],
  ])("%s reports %s", (url, window) => {
    expect(embeddedDetail(url), url).toContain(window);
  });
});
