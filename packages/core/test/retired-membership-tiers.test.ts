import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";

/**
 * LINK-brsntven — `risky_tld` and `bait_tokens`, deleted. Converted guards.
 *
 * This file replaces `bait-tokens.test.ts` and the `risky_tld` slice of
 * `detectors.test.ts`. It follows the precedent §6.1.4 set when
 * `api_endpoint_impersonation` went: the false-positive guards are CONVERTED,
 * not dropped, because the claim they make — "this string must not score" — is
 * unchanged and is now stronger. What changed is that they no longer name a
 * code that cannot be emitted.
 *
 * Both detectors created a scoring finding from curated membership alone:
 *
 *  - `risky_tld` was `publicSuffix` present → `RISKY_TLDS.has(tld)` → emit. A
 *    suffix-presence check and a set lookup, nothing else. Which TLDs are
 *    high-abuse is a fact about the world and about this year.
 *  - `bait_tokens` counted distinct members of a 17-word English lexicon across
 *    the host and path. `normalize(input) === input`, every reader agrees where
 *    `secure-account-verify-login.com` goes, and the string is honest about
 *    itself; the only thing wrong with it is that a reader who knows what
 *    phishing looks like finds it suggestive. That is claim (b), and it is the
 *    same argument architecture §1.1 already makes about `paypal-login.com`.
 *
 * Why deletion rather than weight 0 — the test §6.1.4 supplies is to strip the
 * world-claim and ask what string fact remains. For `credential_harvesting` the
 * OAuth flow shape remained, so it was re-grounded at weight 0. Here nothing
 * remains: the residue of `risky_tld` is "publicSuffix is `tk`", which the
 * parsed result already carries, and the residue of `bait_tokens` is "the host
 * contains English words". And the weight-0 slot already belongs to the CALLER
 * — `denyTlds` emits `tld_denied` at weight 0, and since this change the CLI
 * exposes it as `--deny-tld`.
 */

describe("the two deleted codes are gone from the registry", () => {
  it("neither is a REASON_CODES key", () => {
    expect(Object.keys(REASON_CODES)).not.toContain("risky_tld");
    expect(Object.keys(REASON_CODES)).not.toContain("bait_tokens");
  });
});

describe("converted — the strings `risky_tld` used to flag", () => {
  // The old positives. Each scored 0.15/low from list membership alone.
  const wasFlagged = [
    "https://mycompany.tk",
    "https://promo.tk/",
    "https://promo-login.tk/",
    "https://example.ml/",
    "https://cheap.xyz/",
    "https://deal.top/",
  ];

  for (const input of wasFlagged) {
    it(`${input} scores 0 with no reasons`, () => {
      const r = inspect(input);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons).toEqual([]);
    });
  }

  it("a caller who wants .tk to matter says so, and gets it at weight 0", () => {
    const r = inspect("https://promo.tk/", { denyTlds: ["tk"] });
    const denied = r.reasons.find((x) => x.code === "tld_denied");
    expect(denied?.weight).toBe(0);
    expect(r.score).toBe(0);
  });
});

describe("converted — the strings `bait_tokens` used to flag", () => {
  const wasFlagged = [
    "https://secure-account-verify-login.com",
    "https://secure-login.example.com",
    "https://update-billing.example.tk/confirm/password",
  ];

  for (const input of wasFlagged) {
    it(`${input} scores 0 with no reasons`, () => {
      const r = inspect(input);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons).toEqual([]);
    });
  }

  it("this is the same answer §1.1 already gives for paypal-login.com", () => {
    // The pairing is the point: the bait host and the combosquat differ only in
    // how many suggestive words they carry, and neither is a structural fact.
    expect(inspect("https://paypal-login.com").score).toBe(0);
    expect(inspect("https://secure-account-verify-login.com").score).toBe(0);
  });
});

describe("converted — the SC-2 negatives, which still must not score", () => {
  // These were `forbidReasons: ["bait_tokens"]` guards. The claim is unchanged
  // and no longer names an unemittable code.
  const benign = [
    "https://login.example.com/",
    "https://example.com/account",
    "https://accounts.google.com/signin",
    "https://login.microsoftonline.com/",
    "https://example.com/account/security/signin",
    "https://example.com/account/login",
    "https://www.example.com/path?q=1",
    "https://github.com/anthropics/claude-code",
  ];

  for (const input of benign) {
    it(`${input} stays at score 0`, () => {
      const r = inspect(input);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    });
  }

  it("an IP host with a baity path is still quiet", () => {
    const r = inspect("http://127.0.0.1/secure/account/verify/login");
    expect(r.reasons.map((x) => x.code)).not.toContain("bait_tokens");
  });

  it("empty / whitespace input is unaffected", () => {
    expect(inspect("").reasons.map((x) => x.code)).not.toContain("bait_tokens");
    expect(inspect("   ").reasons.map((x) => x.code)).not.toContain("bait_tokens");
  });
});

describe("what the deletion deliberately does NOT touch", () => {
  it("file_extension_tld still owns .zip/.mov on the masquerade structure", () => {
    const r = inspect("https://invoice.zip/");
    expect(r.reasons.map((x) => x.code)).toEqual(["file_extension_tld"]);
    expect(r.score).toBeCloseTo(0.4, 5);
  });

  it("a structural finding on a .tk host is untouched — only the top-up is gone", () => {
    const r = inspect("https://login.paypal.com.evil.tk");
    expect(r.reasons.map((x) => x.code)).toEqual(["embedded_domain_in_subdomain"]);
    expect(r.score).toBeCloseTo(0.5, 5);
  });

  it("brand_homoglyph still reads the fold in a bait-shaped host", () => {
    const r = inspect("https://paypa1-secure-login.com");
    expect(r.reasons.map((x) => x.code)).toContain("brand_homoglyph");
    expect(r.score).toBeCloseTo(0.8, 5);
  });
});
