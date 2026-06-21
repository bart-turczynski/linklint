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
  it("an /oauth/authorize path on a non-allowlisted host fires", () => {
    expect(
      agentCodes("https://account-verify.example.com/oauth/authorize?client_id=abc"),
    ).toContain("credential_harvesting");
  });

  it("an /oauth/token path on a non-allowlisted host fires", () => {
    expect(agentCodes("https://login.evil.tk/oauth/token")).toContain("credential_harvesting");
  });

  it("a /login/oauth/authorize path on a non-allowlisted host fires", () => {
    expect(agentCodes("https://impostor.example.org/login/oauth/authorize")).toContain(
      "credential_harvesting",
    );
  });

  it("a /connect/authorize path on a non-allowlisted host fires", () => {
    expect(agentCodes("https://sso-portal.example.net/connect/authorize")).toContain(
      "credential_harvesting",
    );
  });

  it("access_token= on a non-allowlisted host fires", () => {
    expect(agentCodes("https://capture.example.com/cb?access_token=xyz")).toContain(
      "credential_harvesting",
    );
  });

  it("client_secret= on a non-allowlisted host fires", () => {
    expect(agentCodes("https://capture.example.com/cb?client_secret=shh")).toContain(
      "credential_harvesting",
    );
  });

  it("redirect_uri= on a non-allowlisted host fires", () => {
    expect(
      agentCodes("https://phish.example.com/auth?redirect_uri=https://evil.example/cb"),
    ).toContain("credential_harvesting");
  });

  it("response_type=token on a non-allowlisted host fires", () => {
    expect(agentCodes("https://phish.example.com/auth?response_type=token")).toContain(
      "credential_harvesting",
    );
  });

  it("code= combined with client_id= on a non-allowlisted host fires", () => {
    expect(agentCodes("https://phish.example.com/cb?code=AUTHCODE&client_id=abc")).toContain(
      "credential_harvesting",
    );
  });
});

describe("credential_harvesting — conservative: known OAuth providers do NOT fire", () => {
  it("accounts.google.com/oauth/authorize does not fire", () => {
    expect(
      agentCodes("https://accounts.google.com/oauth/authorize?client_id=abc&redirect_uri=x"),
    ).not.toContain("credential_harvesting");
  });

  it("github.com/login/oauth/authorize does not fire", () => {
    expect(
      agentCodes("https://github.com/login/oauth/authorize?client_id=abc"),
    ).not.toContain("credential_harvesting");
  });

  it("login.microsoftonline.com token flow does not fire", () => {
    expect(
      agentCodes("https://login.microsoftonline.com/common/oauth2/authorize?response_type=token"),
    ).not.toContain("credential_harvesting");
  });

  it("an okta tenant authorize endpoint does not fire", () => {
    expect(
      agentCodes("https://dev-123.okta.com/oauth2/authorize?client_secret=x"),
    ).not.toContain("credential_harvesting");
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
  it("is weight 0.35", () => {
    const r = inspect("https://phish.example.com/oauth/authorize?client_id=abc", {
      agentMode: true,
    });
    expect(r.reasons.find((x) => x.code === "credential_harvesting")!.weight).toBeCloseTo(0.35, 5);
  });
});
