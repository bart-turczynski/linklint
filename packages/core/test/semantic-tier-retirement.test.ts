import { describe, expect, it } from "vitest";
import * as data from "../src/data.js";
import * as experimental from "../src/experimental.js";
import { inspect } from "../src/index.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { SCHEMA_VERSION } from "../src/schema/base.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";
import { WEIGHTS_VERSION } from "../src/scoring/weights.js";

/**
 * LINK-brsntven — PIN, then mutate.
 *
 * This file is written BEFORE the retirement lands and asserts exactly what the
 * retirement moves: the two membership-only detectors firing, the band the
 * companion signal was buying, the three agent-gated weights §1.1 owes a
 * disposition for, the `DataVersions` field name, the two public data exports,
 * and both version stamps. Every assertion here is expected to go RED when the
 * change is applied, and each one is then rewritten to the post-change value.
 * A pin that does not redden proved nothing.
 */

function verdict(input: string, options?: Parameters<typeof inspect>[1]) {
  const r = inspect(input, options);
  return {
    score: r.score,
    severity: r.severity,
    codes: r.reasons.map((x) => x.code),
    weights: Object.fromEntries(r.reasons.map((x) => [x.code, x.weight])),
  };
}

describe("PIN — the two membership-only detectors fire today", () => {
  it("`risky_tld` is a suffix-presence check plus a set lookup and nothing else", () => {
    const r = verdict("https://mycompany.tk");
    expect(r.codes).toContain("risky_tld");
    expect(r.score).toBeCloseTo(0.15, 5);
    expect(r.severity).toBe("low");
  });

  it("`bait_tokens` fires on a stacked-keyword host", () => {
    const r = verdict("https://secure-account-verify-login.com");
    expect(r.codes).toContain("bait_tokens");
    expect(r.score).toBeCloseTo(0.15, 5);
    expect(r.severity).toBe("low");
  });

  it("both are registered as SCORING codes at 0.15", () => {
    expect(REASON_CODES.risky_tld.scoring).toBe(true);
    expect(REASON_CODES.risky_tld.weight).toBeCloseTo(0.15, 5);
    expect(REASON_CODES.bait_tokens.scoring).toBe(true);
    expect(REASON_CODES.bait_tokens.weight).toBeCloseTo(0.15, 5);
  });
});

describe("PIN — the band the companion signal is buying (amendment 3)", () => {
  // `embedded_domain_in_subdomain` sits EXACTLY on the medium/high edge, so
  // these three rows are `high` only because a 0.15 contextual signal tops them
  // up. Deleting that signal drops each of them one band.
  it("embedded_domain_in_subdomain is the 0.50 tier", () => {
    expect(REASON_CODES.embedded_domain_in_subdomain.weight).toBeCloseTo(0.5, 5);
  });

  it("login.paypal.com.account.evil.com is 0.575/high via bait_tokens", () => {
    const r = verdict("https://login.paypal.com.account.evil.com/");
    expect(r.codes.sort()).toEqual(["bait_tokens", "embedded_domain_in_subdomain"]);
    expect(r.score).toBeCloseTo(0.575, 5);
    expect(r.severity).toBe("high");
  });

  it("login.paypal.com.evil.tk is 0.575/high via risky_tld", () => {
    const r = verdict("https://login.paypal.com.evil.tk");
    expect(r.codes.sort()).toEqual(["embedded_domain_in_subdomain", "risky_tld"]);
    expect(r.score).toBeCloseTo(0.575, 5);
    expect(r.severity).toBe("high");
  });

  it("paypa1-secure-login.com is 0.83/critical via bait_tokens", () => {
    const r = verdict("https://paypa1-secure-login.com");
    expect(r.score).toBeCloseTo(0.83, 5);
    expect(r.severity).toBe("critical");
  });

  it("a.b.c.d.paypal.com.evil-login.tk stacks all three", () => {
    const r = verdict("https://a.b.c.d.paypal.com.evil-login.tk/");
    expect(r.codes.sort()).toEqual([
      "embedded_domain_in_subdomain",
      "excessive_subdomain_depth",
      "risky_tld",
    ]);
    expect(r.score).toBeCloseTo(0.63875, 5);
    expect(r.severity).toBe("high");
  });
});

describe("PIN — the three dispositions §1.1 owes are NOT shipped yet", () => {
  const owed: [ReasonCode, number][] = [
    ["prompt_injection_url", 0.5],
    ["data_exfiltration", 0.3],
    ["credential_harvesting", 0.35],
  ];

  it.each(owed)("`%s` still scores at %s", (code, weight) => {
    expect(REASON_CODES[code].scoring).toBe(true);
    expect(REASON_CODES[code].weight).toBeCloseTo(weight, 5);
  });

  it("prompt_injection_url moves the score under agentMode", () => {
    const r = verdict("https://example.com/?q=ignore+previous+instructions", { agentMode: true });
    expect(r.codes).toContain("prompt_injection_url");
    expect(r.score).toBeCloseTo(0.5, 5);
    expect(r.severity).toBe("medium");
  });

  it("credential_harvesting is gated OFF by the inverse provider allowlist", () => {
    const impostor =
      "https://evil.com/oauth/authorize?response_type=code&client_id=x&redirect_uri=https://evil.com/cb";
    const provider =
      "https://github.com/login/oauth/authorize?response_type=code&client_id=x&redirect_uri=https://x/cb";
    expect(verdict(impostor, { agentMode: true }).codes).toContain("credential_harvesting");
    // The allowlist half — this is the inverse watchlist the retirement drops.
    expect(verdict(provider, { agentMode: true }).codes).not.toContain("credential_harvesting");
  });

  it("data_exfiltration scores its overlong-token branch under agentMode", () => {
    const r = verdict("https://collect.example.com/p?exfil=secretdata", { agentMode: true });
    expect(r.codes).toContain("data_exfiltration");
    expect(r.weights.data_exfiltration).toBeCloseTo(0.3, 5);
  });
});

describe("PIN — the data stamp and the public exports", () => {
  it("`DataVersions` carries `riskyTlds` and no `fileExtensionTlds`", () => {
    expect(DATA_VERSIONS).toHaveProperty("riskyTlds");
    expect(DATA_VERSIONS).not.toHaveProperty("fileExtensionTlds");
  });

  it("`linklint/data` exports RISKY_TLDS beside FILE_EXTENSION_TLDS", () => {
    expect(Object.keys(data)).toContain("RISKY_TLDS");
    expect(Object.keys(data)).toContain("FILE_EXTENSION_TLDS");
  });

  it("`linklint/experimental` exports the two detectors", () => {
    expect(Object.keys(experimental)).toContain("riskyTld");
    expect(Object.keys(experimental)).toContain("baitTokens");
  });
});

describe("PIN — both version stamps, before the one bump for the lot", () => {
  it("SCHEMA_VERSION is 1.9 and WEIGHTS_VERSION is 1.18", () => {
    expect(SCHEMA_VERSION).toBe("1.9");
    expect(WEIGHTS_VERSION).toBe("1.18");
  });
});
