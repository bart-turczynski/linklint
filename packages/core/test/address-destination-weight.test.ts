import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { WEIGHTS_VERSION } from "../src/scoring/weights.js";

/**
 * LINK-bwqhvjcs — PIN, then mutate. The pre-change half: every assertion states
 * the CURRENT behaviour of the destination-membership ip_* codes, so the change
 * that follows is visible as a diff of this file.
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

describe("destination-membership codes — current weights", () => {
  it("registry weights", () => {
    expect(REASON_CODES.ip_cloud_metadata.weight).toBe(0.75);
    expect(REASON_CODES.ip_loopback.weight).toBe(0.2);
    expect(REASON_CODES.ip_private.weight).toBe(0.2);
    expect(REASON_CODES.ip_link_local.weight).toBe(0.2);
    expect(REASON_CODES.ip_reserved.weight).toBe(0.2);
  });

  it("form codes keep their weights", () => {
    expect(REASON_CODES.ip_obfuscation.weight).toBe(0.4);
    expect(REASON_CODES.ambiguous_numeric_host.weight).toBe(0.3);
    expect(REASON_CODES.ssrf_cloud_metadata.weight).toBe(1);
  });

  it("WEIGHTS_VERSION", () => {
    expect(WEIGHTS_VERSION).toBe("1.22");
  });
});

describe("destination-membership codes — current verdicts", () => {
  it("169.254.169.254 lands high by default", () => {
    const r = verdict("http://169.254.169.254/");
    expect(r.codes).toEqual(["ip_cloud_metadata"]);
    expect(r.score).toBeCloseTo(0.75, 5);
    expect(r.severity).toBe("high");
  });

  it("169.254.169.254 lands critical under agentMode", () => {
    const r = verdict("http://169.254.169.254/", { agentMode: true });
    expect(r.codes).toEqual(["ssrf_cloud_metadata", "ip_cloud_metadata"]);
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
  });

  it("192.168.1.1 scores 0.20/low", () => {
    const r = verdict("http://192.168.1.1/");
    expect(r.codes).toEqual(["ip_private"]);
    expect(r.score).toBeCloseTo(0.2, 5);
    expect(r.severity).toBe("low");
  });

  it("2130706433 scores 0.52/high (obfuscation + loopback)", () => {
    const r = verdict("http://2130706433/");
    expect(r.codes).toEqual(["ip_obfuscation", "ip_loopback"]);
    expect(r.score).toBeCloseTo(0.52, 5);
    expect(r.severity).toBe("high");
  });
});
