import { describe, expect, it } from "vitest";
import { inspect, openRedirectParamTargets } from "../src/index.js";

/**
 * LINK-cvcjgewz — the `open_redirect_param` divergence gate.
 *
 * COMMIT 1 OF 2. This file is written as a CHARACTERIZATION pin: it records the
 * behavior of the gate as it stands on `main`, defects included, so the commit
 * that changes it has to change these assertions and cannot drift silently.
 *
 * The gate fires only when the decoded target's registrable domain is non-null
 * AND differs from the input's. Two defects fall out of that single clause and
 * are pinned below exactly as they behave today:
 *
 *   DEFECT 1 (under-fires) — an IP literal has a NULL registrable domain, so
 *     every IP-literal redirect target is silently exempt. The bare IMDS address
 *     scores 1.00/critical under agentMode; wrapped in `?url=` it scores 0.00.
 *   DEFECT 2 (over-fires) — `redirect_uri` is a plain member of REDIRECT_PARAMS,
 *     so every standards-shaped OAuth authorize URL trips the gate at 0.40,
 *     even though a cross-registrable-domain handoff is the whole protocol.
 *
 * The true positives in the first block are the recall floor: they must survive
 * whatever the fix does.
 */

const codes = (input: string): string[] => inspect(input).reasons.map((r) => r.code);
const fires = (input: string): boolean => codes(input).includes("open_redirect_param");

describe("LINK-cvcjgewz pin — true positives that must survive the fix", () => {
  const mustFire = [
    "https://example.com/login?next=https://evil.com/phish",
    "https://example.com/?redirect=//evil.com/x",
    "https://example.com/?url=https%253A%252F%252Fevil.com%252Fp",
    "https://example.com/?GoTo=https://evil.com",
    "https://example.com/?redirect_url=https://evil.com",
    "https://example.com/?redirect_uri=https://evil.com",
    "https://example.com/?dest=https://evil.com",
    "https://example.com/?continue=https://evil.com",
  ];
  for (const input of mustFire) {
    it(`fires for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(true);
    });
  }

  it("carries weight 0.4 and names both authorities", () => {
    const r = inspect("https://example.com/login?next=https://evil.com/phish");
    const reason = r.reasons.find((x) => x.code === "open_redirect_param")!;
    expect(reason.weight).toBeCloseTo(0.4, 5);
    expect(reason.detail).toContain("evil.com");
    expect(reason.detail).toContain("example.com");
  });
});

describe("LINK-cvcjgewz pin — same-authority and non-payload values stay clean", () => {
  const mustNotFire = [
    "https://example.com/?next=https://example.com/home",
    "https://example.com/?next=https://app.example.com/home",
    "https://example.com/?next=/dashboard",
    "https://example.com/?redirect=%2Fhome",
    "https://example.com/?ref=https://evil.com",
    "https://example.com/?url=2",
    "https://example.com/?next=",
    "https://example.com/",
  ];
  for (const input of mustNotFire) {
    it(`stays clean for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(false);
    });
  }

  it("never throws on a junk value", () => {
    expect(() => inspect("https://example.com/?next=%%%not-a-url%%%")).not.toThrow();
    expect(fires("https://example.com/?next=%%%not-a-url%%%")).toBe(false);
  });
});

describe("LINK-cvcjgewz pin — DEFECT 1: every IP-literal target is silently exempt", () => {
  // A null registrable domain slips past `targetDomain === null` and the whole
  // SSRF-to-IMDS pivot scores zero. PINNED AS THE CURRENT (WRONG) BEHAVIOR.
  const exemptToday = [
    "https://example.com/login?url=http://169.254.169.254/",
    "https://example.com/login?next=http://169.254.169.254/",
    "https://example.com/login?url=http://127.0.0.1/",
    "https://example.com/login?url=http://localhost/",
    "https://example.com/login?url=http://[::1]/",
    "https://example.com/login?url=http://2130706433/",
    "https://example.com/login?url=http://10.0.0.5:8080/admin",
    "https://example.com/login?redirect=//169.254.169.254/latest/meta-data/",
  ];
  for (const input of exemptToday) {
    it(`does NOT fire (today) for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(false);
    });
  }

  it("the bare IMDS address DOES score, so the redirect wrapper is the hole", () => {
    const bare = inspect("http://169.254.169.254/latest/meta-data/", { agentMode: true });
    expect(bare.score).toBe(1);
    expect(bare.severity).toBe("critical");
    const wrapped = inspect("https://example.com/login?url=http://169.254.169.254/", {
      agentMode: true,
    });
    expect(wrapped.score).toBe(0);
  });

  it("an IP-literal INPUT host is exempt on the other side too (today)", () => {
    // `inputRegistrableDomainLower === null` short-circuits the whole scan.
    expect(fires("http://198.51.100.7/?next=https://evil.com/phish")).toBe(false);
  });
});

describe("LINK-cvcjgewz pin — DEFECT 2: standards-shaped OAuth authorize URLs fire", () => {
  // A cross-registrable-domain handoff IS the OAuth authorization-code flow.
  // PINNED AS THE CURRENT (WRONG) BEHAVIOR.
  const falsePositivesToday = [
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&redirect_uri=https://myapp.io/cb",
    "https://github.com/login/oauth/authorize?client_id=x&redirect_uri=https://vercel.com/cb",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&response_type=code&redirect_uri=https://contoso.io/cb",
    "https://slack.com/oauth/v2/authorize?client_id=x&scope=chat:write&redirect_uri=https://myapp.io/cb",
  ];
  for (const input of falsePositivesToday) {
    it(`DOES fire (today) for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(true);
      expect(inspect(input).severity).toBe("medium");
    });
  }
});

describe("LINK-cvcjgewz pin — shapes an OAuth carve-out must NOT swallow", () => {
  // These fire today and must still fire after the fix: a `client_id` bolted
  // onto a NON-OAuth redirect parameter is not an authorization request.
  const mustKeepFiring = [
    "https://example.com/login?next=https://evil.com&client_id=x",
    "https://example.com/login?redirect_url=https://evil.com&client_id=x",
    "https://example.com/login?url=https://evil.com&client_id=x&response_type=code",
    "https://example.com/login?redirect_uri=https://evil.com",
  ];
  for (const input of mustKeepFiring) {
    it(`fires for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(true);
    });
  }
});

describe("LINK-cvcjgewz pin — openRedirectParamTargets contract (Layer 2 consumer)", () => {
  // packages/online correlates an OBSERVED landing registrable domain against
  // these targets, so the exported shape must keep a non-null string domain.
  it("returns the param + registrable domain of an off-site payload", () => {
    expect(openRedirectParamTargets("next=https://evil.com/phish", "example.com")).toEqual([
      { param: "next", registrableDomain: "evil.com" },
    ]);
  });

  it("returns nothing for a same-registrable-domain payload", () => {
    expect(openRedirectParamTargets("next=https://app.example.com/x", "example.com")).toEqual([]);
  });

  it("returns nothing for an IP-literal payload (no registrable domain to correlate)", () => {
    expect(openRedirectParamTargets("url=http://169.254.169.254/", "example.com")).toEqual([]);
  });

  it("returns nothing when the input has no registrable domain", () => {
    expect(openRedirectParamTargets("next=https://evil.com", null)).toEqual([]);
  });
});
