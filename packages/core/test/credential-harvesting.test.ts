import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// Agent-gated detector: every assertion runs `inspect(url, { agentMode: true })`
// because the detector is silent by default (gating is exercised in the contract
// test). Here we test the SIGNAL boundary: an OAuth/token shape on a NON-allowlisted
// host fires, the SAME shape on a known OAuth provider does NOT, and a benign URL
// without these markers stays clean.

const agentReasons = (input: string) => inspect(input, { agentMode: true }).reasons;
const agentCodes = (input: string): string[] => agentReasons(input).map((r) => r.code);

describe("credential_harvesting — OAuth/token shape on an unknown host FIRES (agentMode)", () => {
  it("an /oauth/authorize path fires", () => {
    expect(
      agentCodes("https://account-verify.example.com/oauth/authorize?client_id=abc"),
    ).toContain("credential_harvesting");
  });

  it("an /oauth/token path fires", () => {
    expect(agentCodes("https://login.evil.tk/oauth/token")).toContain("credential_harvesting");
  });

  it("a /login/oauth/authorize path fires", () => {
    expect(agentCodes("https://impostor.example.org/login/oauth/authorize")).toContain(
      "credential_harvesting",
    );
  });

  it("a /connect/authorize path fires", () => {
    expect(agentCodes("https://sso-portal.example.net/connect/authorize")).toContain(
      "credential_harvesting",
    );
  });

  it("access_token= fires", () => {
    expect(agentCodes("https://capture.example.com/cb?access_token=xyz")).toContain(
      "credential_harvesting",
    );
  });

  it("client_secret= fires", () => {
    expect(agentCodes("https://capture.example.com/cb?client_secret=shh")).toContain(
      "credential_harvesting",
    );
  });

  it("redirect_uri= fires", () => {
    expect(
      agentCodes("https://phish.example.com/auth?redirect_uri=https://evil.example/cb"),
    ).toContain("credential_harvesting");
  });

  it("response_type=token fires", () => {
    expect(agentCodes("https://phish.example.com/auth?response_type=token")).toContain(
      "credential_harvesting",
    );
  });

  it("code= combined with client_id= fires", () => {
    expect(agentCodes("https://phish.example.com/cb?code=AUTHCODE&client_id=abc")).toContain(
      "credential_harvesting",
    );
  });
});

// CONVERTED (LINK-brsntven). This block used to assert that a curated set of
// ~21 real identity providers was gated OFF — an INVERSE watchlist, where the
// finding was created by a registrable domain's ABSENCE from a hand-kept
// commercial list. §1.1's name-never-create rule forbids that in either
// polarity, and §6.1.4 already deleted its mirror image. The allowlist is gone,
// so the claim these rows make is inverted: the flow shape is true of
// github.com as well, and saying so at weight 0 costs nothing.
describe("credential_harvesting — the real providers report too, at weight 0", () => {
  const providers = [
    "https://accounts.google.com/oauth/authorize?client_id=abc&redirect_uri=x",
    "https://github.com/login/oauth/authorize?client_id=abc",
    "https://login.microsoftonline.com/common/oauth2/authorize?response_type=token",
    "https://dev-123.okta.com/oauth2/authorize?client_secret=x",
  ];

  it.each(providers)("%s reports the shape", (url) => {
    expect(agentCodes(url)).toContain("credential_harvesting");
  });

  it.each(providers)("%s is not scored for it", (url) => {
    const r = inspect(url, { agentMode: true });
    const reason = r.reasons.find((x) => x.code === "credential_harvesting");
    expect(reason?.weight).toBe(0);
  });

  it("the detail no longer asserts anything about who is a real provider", () => {
    const detail =
      inspect("https://github.com/login/oauth/authorize?client_id=abc", { agentMode: true }).reasons.find(
        (x) => x.code === "credential_harvesting",
      )?.detail ?? "";
    expect(detail).not.toContain("not a known OAuth");
    expect(detail).not.toContain("non-allowlisted");
    expect(detail).toContain("github.com");
  });

  it("an impostor host and a real provider are now reported identically", () => {
    // The control §6.1.4 asked for: two strings a URL parser cannot tell apart
    // must not receive different verdicts because of a curated list.
    const impostor = inspect("https://login-portal.example.com/oauth/authorize?client_id=abc", {
      agentMode: true,
    });
    const provider = inspect("https://github.com/login/oauth/authorize?client_id=abc", {
      agentMode: true,
    });
    expect(impostor.score).toBe(provider.score);
    expect(impostor.severity).toBe(provider.severity);
  });
});

describe("credential_harvesting — conservative: benign + non-marker URLs do NOT fire", () => {
  it("a benign URL without OAuth/token markers is clean", () => {
    expect(agentCodes("https://www.example.com/dashboard?page=2")).not.toContain(
      "credential_harvesting",
    );
  });

  it("code= alone (no client_id=) does not fire", () => {
    expect(agentCodes("https://example.com/redeem?code=PROMO50")).not.toContain(
      "credential_harvesting",
    );
  });

  it("response_type=code (authorization-code, not implicit token) without the pair does not fire", () => {
    expect(agentCodes("https://example.com/auth?response_type=code")).not.toContain(
      "credential_harvesting",
    );
  });

  it("a path that merely contains 'oauth' as a substring does not fire", () => {
    expect(agentCodes("https://example.com/myoauth/authorizenow")).not.toContain(
      "credential_harvesting",
    );
  });

  it("an IP host does not fire", () => {
    expect(agentCodes("https://127.0.0.1/oauth/authorize")).not.toContain("credential_harvesting");
  });
});

describe("credential_harvesting — weight", () => {
  it("is weight 0 — it reports, it does not score (LINK-brsntven)", () => {
    const r = inspect("https://phish.example.com/oauth/authorize?client_id=abc", {
      agentMode: true,
    });
    expect(r.reasons.find((x) => x.code === "credential_harvesting")!.weight).toBe(0);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });
});
