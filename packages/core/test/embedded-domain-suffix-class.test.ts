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
 * The firing condition is now the window suffix's DELEGATION ERA: a bare legacy
 * gTLD or a multi-label ccTLD suffix scores, and everything delegated from the
 * 2000 expansion round onward is skipped. Blocks 1 and 3 were pinned to the
 * pre-narrowing behaviour in the preceding commit and are inverted here, so the
 * change reads as an edit to an existing assertion rather than as a new test
 * arriving green. Block 2 is unchanged and pins what had to survive.
 */

const embeddedDetail = (url: string): string | undefined =>
  inspect(url).reasons.find((r) => r.code === "embedded_domain_in_subdomain")?.detail;

const fired = (url: string): boolean => embeddedDetail(url) !== undefined;

// ── 1. Ordinary hosts on an expansion-gTLD window ───────────────────────────
// Every hostname here is real and was drawn from the CrUX top-1M browsed-origins
// corpus by the LINK-kgiviycg measurement, not invented. Each used to score
// 0.50/medium on this rule alone, and each 0.50 stacked under probabilistic-OR
// with any other finding on the same URL. Every assertion in this block was RED
// before the suffix-class gate landed.
describe("LINK-vuqdzmzy — expansion-gTLD windows on ordinary hosts stay clean", () => {
  it.each([
    "https://console.cloud.google.com/", // Google Cloud Console
    "https://www.tax.service.gov.uk/", // HMRC
    "https://n.news.naver.com/", // Naver News
    "https://in.search.yahoo.com/",
    "https://m.place.naver.com/",
    "https://m.cafe.daum.net/",
    "https://a24.app.gree-pf.net/",
    "https://rof.x3.international.travian.com/",
    "https://api.dev.example.com/",
  ])("%s stays clean", (url) => {
    expect(fired(url), url).toBe(false);
  });

  it("the Google Cloud Console scores 0.00/info", () => {
    const r = inspect("https://console.cloud.google.com/");
    expect(r.reasons.map((x) => x.code)).toEqual([]);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  // Pre-2012 expansion and sponsored gTLDs are the same phenomenon: `.post`
  // (2011) and `.travel` (2005) predate the 2012 round entirely, and measure
  // like the 2012 round rather than like `.com`. A cut drawn at "the 2012
  // round" would have been drawn in the wrong place.
  it.each([
    "https://www.post.japanpost.jp/", // Japan Post
    "https://hotel.travel.rakuten.co.jp/", // Rakuten Travel
    "https://pro.store.yahoo.co.jp/",
    "https://www.jobs.example.com/",
    "https://www.info.example.com/",
  ])("%s stays clean on a pre-2012 expansion window", (url) => {
    expect(fired(url), url).toBe(false);
  });

  // A brand gTLD is an expansion gTLD too: `.amazon` was delegated in the 2012
  // round, so Amazon's real Belgian storefront stops firing on `www.amazon`.
  it("Amazon's real Belgian storefront scores 0.00/info", () => {
    const r = inspect("https://www.amazon.com.be/");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  // `in-addr.arpa` is a multi-label suffix under a legacy gTLD, not under a
  // ccTLD, so the multi-label carve-out does not reach it: reverse-DNS naming
  // is not an authority claim and its measured LR is 0.00.
  it("a reverse-DNS window under in-addr.arpa stays clean", () => {
    expect(fired("https://1.2.3.in-addr.arpa.evil.com/")).toBe(false);
  });

  // Negative control for the gate itself: `metadata` is not a public suffix, so
  // this host was clean before the change too, which shows the gate is not what
  // silences it.
  it("a window whose right label is not a public suffix never reached the gate", () => {
    expect(fired("https://api.metadata.example.com/")).toBe(false);
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
// left-to-right, so the `.apple` window used to win and `apple.com` was never
// reached. Because a skipped window does not abort the scan, the `.com` window
// to its right is now the one reported — the host keeps firing, on the class
// that carries the signal.
//
// This is why the measured recall cost is 3.05% of at-risk phishing hosts and
// not the 3.49% a count of currently-reported windows predicts: `appleid.apple`
// alone covered 85 phishDB hosts, 64 of which the `.com` window still catches.
describe("LINK-vuqdzmzy — a skipped brand-gTLD window falls through to the .com window", () => {
  it.each([
    ["https://appleid.apple.com.evil.tk/", "apple.com", "appleid.apple"],
    ["https://accounts.google.com.evil.tk/", "google.com", "accounts.google"],
  ])("%s reports %s instead of %s", (url, reported, shadowed) => {
    const detail = embeddedDetail(url);
    expect(detail, url).toContain(reported);
    expect(detail, url).not.toContain(shadowed);
  });

  it("still reaches the medium band", () => {
    expect(inspect("https://appleid.apple.com.evil.tk/").severity).toBe("medium");
  });
});
