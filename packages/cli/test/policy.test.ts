import { describe, expect, it } from "vitest";
import { inspect, type InspectResult } from "linklint";
import {
  isSeverity,
  resolveExitCode,
  SEVERITY_ORDER,
  severityRank,
  VALID_FAIL_ON,
} from "@linklint/cli";

// Real fixtures from the core engine.
const benign: InspectResult = inspect("https://www.example.com/path"); // info / 0
const medium: InspectResult = inspect("https://paypal.com@evil.example.com/login"); // medium
// LINK-brsntven note: the previous `high` fixture was
// `https://www.gооgle.com@bad.tk/login`, which reached 0.575/high only because
// `risky_tld` added 0.15 on top of `userinfo_present` — the Cyrillic homoglyphs
// sit in the USERINFO, not the host, so nothing else fired. With `risky_tld`
// deleted it reads 0.500/medium and stopped exercising the `high` band. The
// replacement is a deep-subdomain phish that reaches `high` from two structural
// findings and no membership lookup.
const high: InspectResult = inspect("https://a.b.c.d.paypal.com.evil-login.tk/"); // high
const invalid: InspectResult = inspect("ht!tp://%%%not a url"); // invalid

describe("severity helpers", () => {
  it("severityRank orders by SEVERITY_ORDER", () => {
    expect(severityRank("info")).toBe(0);
    expect(severityRank("critical")).toBe(SEVERITY_ORDER.length - 1);
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
  });

  it("isSeverity / VALID_FAIL_ON agree", () => {
    expect(isSeverity("medium")).toBe(true);
    expect(isSeverity("nope")).toBe(false);
    expect([...VALID_FAIL_ON].sort()).toEqual([...SEVERITY_ORDER].sort());
  });

  it("the fixtures have the expected severities", () => {
    expect(benign.severity).toBe("info");
    expect(medium.severity).toBe("medium");
    expect(high.severity).toBe("high");
    expect(invalid.status).toBe("invalid");
  });
});

describe("resolveExitCode", () => {
  it("empty results => 0", () => {
    expect(resolveExitCode([], { failOn: "high", allowInvalid: false })).toBe(0);
  });

  it("below threshold => 0", () => {
    expect(resolveExitCode([benign], { failOn: "high", allowInvalid: false })).toBe(0);
  });

  it("at/above threshold => 1", () => {
    expect(resolveExitCode([high], { failOn: "high", allowInvalid: false })).toBe(1);
  });

  it("invalid => 1 (fail-closed)", () => {
    expect(resolveExitCode([invalid], { failOn: "high", allowInvalid: false })).toBe(1);
  });

  it("invalid + allowInvalid => 0", () => {
    expect(resolveExitCode([invalid], { failOn: "high", allowInvalid: true })).toBe(0);
  });

  it("mixed picks the worst outcome", () => {
    expect(resolveExitCode([benign, high, benign], { failOn: "high", allowInvalid: false })).toBe(
      1,
    );
  });

  describe("--fail-on threshold boundary (a MEDIUM result)", () => {
    it("failOn medium => 1 (at threshold)", () => {
      expect(resolveExitCode([medium], { failOn: "medium", allowInvalid: false })).toBe(1);
    });

    it("failOn high => 0 (below threshold)", () => {
      expect(resolveExitCode([medium], { failOn: "high", allowInvalid: false })).toBe(0);
    });
  });
});
