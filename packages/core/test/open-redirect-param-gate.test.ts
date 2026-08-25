import { describe, expect, it } from "vitest";
import { inspect, openRedirectParamTargets } from "../src/index.js";

/**
 * LINK-cvcjgewz — the `open_redirect_param` divergence gate.
 *
 * COMMIT 2 OF 2. The previous commit pinned this file to the behavior of `main`,
 * defects included. Every assertion below that changed sign is annotated FLIPPED,
 * so the diff of this file IS the behavior change.
 *
 * DEFECT 1 (was under-firing) — the gate required a non-null registrable domain
 *   on the target, and an IP literal has none, so every IP-literal redirect
 *   target was exempt. The bare IMDS address scores 1.00/critical under
 *   agentMode; wrapped in `?url=` it scored 0.00. Divergence is now decided over
 *   AUTHORITY (registrable domain, else canonical IP, else bare host), which is
 *   total, so IP-literal targets — and IP-literal INPUT hosts — are decidable.
 *
 * DEFECT 2 (was over-firing) — `redirect_uri` was a plain member of
 *   REDIRECT_PARAMS, so every standards-shaped OAuth authorize URL tripped the
 *   gate at 0.40/medium. The exact RFC 6749 spelling `redirect_uri` alongside a
 *   non-empty `client_id`, pointing at a public-DNS target, is now read as an
 *   authorization request rather than a lure. No IdP list is involved: the
 *   discriminator is the shape of the request, from the string alone.
 */

const codes = (input: string): string[] => inspect(input).reasons.map((r) => r.code);
const fires = (input: string): boolean => codes(input).includes("open_redirect_param");
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "open_redirect_param")?.detail ?? "";

describe("LINK-cvcjgewz — true positives that survive the fix", () => {
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

describe("LINK-cvcjgewz — same-authority and non-payload values stay clean", () => {
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

describe("LINK-cvcjgewz — DEFECT 1 FIXED: IP-literal targets are no longer exempt", () => {
  // FLIPPED: every one of these was pinned `false` in the previous commit.
  const nowFires = [
    "https://example.com/login?url=http://169.254.169.254/",
    "https://example.com/login?next=http://169.254.169.254/latest/meta-data/",
    "https://example.com/login?url=http://127.0.0.1/",
    "https://example.com/login?url=http://localhost/",
    "https://example.com/login?url=http://[::1]/",
    "https://example.com/login?url=http://2130706433/",
    "https://example.com/login?url=http://10.0.0.5:8080/admin",
    "https://example.com/login?url=http://192.168.0.1/router",
    "https://example.com/login?redirect=//169.254.169.254/latest/meta-data/",
    "https://example.com/login?url=http://[fd00:ec2::254]/",
    "https://example.com/login?next=http%3A%2F%2F169.254.169.254%2F",
  ];
  for (const input of nowFires) {
    it(`fires for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(true);
    });
  }

  it("the SSRF-to-IMDS pivot no longer scores zero through the wrapper", () => {
    // FLIPPED: the wrapped form was pinned at score 0.
    const bare = inspect("http://169.254.169.254/latest/meta-data/", { agentMode: true });
    expect(bare.score).toBe(1);
    expect(bare.severity).toBe("critical");
    const wrapped = inspect("https://example.com/login?url=http://169.254.169.254/", {
      agentMode: true,
    });
    expect(wrapped.score).toBeGreaterThan(0);
    expect(codes(wrapped.input)).toContain("open_redirect_param");
  });

  it("names the target host and says it has no registrable domain", () => {
    const d = detail("https://example.com/login?url=http://169.254.169.254/");
    expect(d).toContain("169.254.169.254");
    expect(d).toContain("no registrable domain");
    expect(d).toContain("example.com");
  });

  it("an IP-literal INPUT host no longer hides an off-site payload", () => {
    // FLIPPED: `inputRegistrableDomainLower === null` used to short-circuit.
    expect(fires("http://198.51.100.7/?next=https://evil.com/phish")).toBe(true);
  });

  it("compares IP authorities canonically, not by spelling", () => {
    // Same authority in two spellings — must NOT fire.
    expect(fires("http://127.0.0.1:3000/?next=http://127.0.0.1:3000/home")).toBe(false);
    expect(fires("http://127.0.0.1/?next=http://2130706433/x")).toBe(false);
    expect(fires("http://[::1]/?next=http://[0:0:0:0:0:0:0:1]/x")).toBe(false);
    expect(fires("http://192.168.1.10/?redirect=http://192.168.1.10/setup")).toBe(false);
    // Different authority in the obfuscated spelling — must fire.
    expect(fires("http://127.0.0.1/?next=http://169.254.169.254/")).toBe(true);
  });

  it("a bare non-PSL name is one authority with itself", () => {
    expect(fires("http://localhost:8080/login?next=http://localhost:8080/app")).toBe(false);
    expect(fires("http://localhost:8080/login?next=http://intranet/app")).toBe(true);
  });
});

describe("LINK-cvcjgewz — DEFECT 2 FIXED: standards-shaped authorize URLs stay clean", () => {
  // FLIPPED: every one of these was pinned `true` (0.40/medium) previously.
  const nowClean = [
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&redirect_uri=https://myapp.io/cb",
    "https://github.com/login/oauth/authorize?client_id=x&redirect_uri=https://vercel.com/cb",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&response_type=code&redirect_uri=https://contoso.io/cb",
    "https://slack.com/oauth/v2/authorize?client_id=x&scope=chat:write&redirect_uri=https://myapp.io/cb",
    "https://connect.stripe.com/oauth/authorize?response_type=code&client_id=ca_1&redirect_uri=https://myapp.io/cb",
    "https://tenant.auth0.com/authorize?response_type=code&client_id=abc&redirect_uri=https://myapp.io/callback",
    "https://shop.myshopify.com/admin/oauth/authorize?client_id=k&scope=read_products&redirect_uri=https://partner.io/cb",
  ];
  for (const input of nowClean) {
    it(`stays clean for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(false);
    });
  }

  it("drops the whole 0.40 band, not just the reason", () => {
    // Asserted on a host that carries no unrelated signal of its own —
    // `auth0.com` above independently trips ascii_homoglyph on its digit.
    expect(
      inspect(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&redirect_uri=https://myapp.io/cb",
      ).score,
    ).toBe(0);
  });

  it("the exemption is derived from the request shape, not from the host", () => {
    // Same shape on an arbitrary host is equally exempt: no IdP list exists.
    expect(fires("https://random-startup.example/authorize?client_id=1&redirect_uri=https://cb.example.net/x")).toBe(false);
    // …and the same host with a non-authorize redirect payload still fires.
    expect(fires("https://accounts.google.com/x?next=https://evil.com")).toBe(true);
  });
});

describe("LINK-cvcjgewz — the OAuth exemption is narrow by construction", () => {
  const mustKeepFiring = [
    // A `client_id` bolted onto a NON-OAuth redirect parameter suppresses nothing.
    "https://example.com/login?next=https://evil.com&client_id=x",
    "https://example.com/login?redirect_url=https://evil.com&client_id=x",
    "https://example.com/login?url=https://evil.com&client_id=x&response_type=code",
    // `redirect_uri` without a `client_id` is not an authorization request.
    "https://example.com/login?redirect_uri=https://evil.com",
    // An empty `client_id` is not the RFC 6749 marker.
    "https://example.com/login?redirect_uri=https://evil.com&client_id=",
    // The exemption is per-parameter: the second payload still fires.
    "https://idp.example.org/authorize?client_id=x&redirect_uri=https://myapp.io/cb&next=https://evil.com",
    // An authorize request pointing at an IP literal is NOT a web-app handoff.
    "https://example.com/login?redirect_uri=http://169.254.169.254/&client_id=x",
    "https://example.com/login?redirect_uri=http://127.0.0.1:8080/admin&client_id=x&response_type=code",
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&redirect_uri=http://169.254.169.254/",
  ];
  for (const input of mustKeepFiring) {
    it(`fires for ${JSON.stringify(input)}`, () => {
      expect(fires(input)).toBe(true);
    });
  }
});

describe("LINK-cvcjgewz — openRedirectParamTargets contract (Layer 2 consumer)", () => {
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

  it("drops an exempted authorize payload so Layer 2 cannot resurrect it", () => {
    expect(
      openRedirectParamTargets("client_id=x&redirect_uri=https://myapp.io/cb", "google.com"),
    ).toEqual([]);
  });
});
