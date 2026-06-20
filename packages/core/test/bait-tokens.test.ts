import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const baitDetail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "bait_tokens")?.detail ?? "";

describe("G4 bait_tokens — phishing-bait keyword density in host/path", () => {
  it("a host stacking >=3 distinct bait words fires", () => {
    expect(codes("https://secure-account-verify-login.com")).toContain("bait_tokens");
    const d = baitDetail("https://secure-account-verify-login.com");
    expect(d).toContain("account");
    expect(d).toContain("verify");
    expect(d).toContain("secure");
  });

  it("a host with exactly 2 distinct bait tokens fires on the host threshold", () => {
    expect(codes("https://secure-login.example.com")).toContain("bait_tokens");
  });

  it("a baity host+path combo reaching 3 distinct tokens fires", () => {
    // 1 host bait (update) + 2 distinct path bait (confirm, password) = 3 total.
    expect(codes("https://update-billing.example.tk/confirm/password")).toContain("bait_tokens");
    const d = baitDetail("https://update-billing.example.tk/confirm/password");
    expect(d).toContain("path");
    expect(d).toContain("host");
  });

  it("carries the low bait_tokens weight (0.15)", () => {
    const reason = inspect("https://secure-account-verify-login.com").reasons.find(
      (x) => x.code === "bait_tokens",
    )!;
    expect(reason.weight).toBeCloseTo(0.15, 5);
  });

  it("layer is lexical", () => {
    const reason = inspect("https://secure-account-verify-login.com").reasons.find(
      (x) => x.code === "bait_tokens",
    )!;
    expect(reason.layer).toBe("lexical");
  });
});

describe("G4 bait_tokens — negatives that MUST stay quiet (SC-2)", () => {
  const benign = [
    "https://login.example.com/", // single host bait token
    "https://example.com/account", // single path bait token
    "https://accounts.google.com/signin", // legit login: account (host) + signin (path) = 2 distinct, no host>=2
    "https://login.microsoftonline.com/", // single host bait token
    "https://example.com/account/security/signin", // legit deep login path: 2 path bait (account, signin), 0 host
    "https://www.example.com/path?q=1", // no bait at all
    "https://github.com/anthropics/claude-code", // ordinary repo
  ];
  for (const input of benign) {
    it(`no bait_tokens for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("bait_tokens");
    });
  }

  it("does not fire on an IP host even with a baity path", () => {
    expect(codes("http://127.0.0.1/secure/account/verify/login")).not.toContain("bait_tokens");
  });

  it("does not fire on empty / unparseable input", () => {
    expect(codes("")).not.toContain("bait_tokens");
    expect(codes("   ")).not.toContain("bait_tokens");
  });
});
