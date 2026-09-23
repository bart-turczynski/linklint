import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { WEIGHTS_VERSION } from "../src/scoring/weights.js";

/**
 * LINK-bwqhvjcs — PIN, then mutate. The post-change half.
 *
 * Every assertion here was first written against the pre-change behaviour
 * (ip_cloud_metadata 0.75, the four range codes 0.20, WEIGHTS_VERSION 1.22) and
 * watched go RED when the demotion landed. Each is now rewritten to the
 * post-change value, so the file stays the standing guard over exactly the
 * surface the demotion moved.
 *
 * The rule (architecture §6.1.10): a code that fires on WHERE an address points
 * — membership of a range or of the cloud-endpoint table — names no property of
 * the string's form, so it is outside claim (a) and reports at weight 0. A code
 * that reads HOW the address is written (`ip_obfuscation`,
 * `ambiguous_numeric_host`) is form 1 / form 2 and keeps its weight. Agent
 * mode's `ssrf_cloud_metadata` is the one consequence-weighted escalation and
 * keeps scoring.
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

const DESTINATION_CODES = [
  "ip_cloud_metadata",
  "ip_loopback",
  "ip_private",
  "ip_link_local",
  "ip_reserved",
] as const;

describe("destination-membership codes report at weight 0", () => {
  it("registry: weight 0, scoring false", () => {
    for (const code of DESTINATION_CODES) {
      expect(REASON_CODES[code].weight, code).toBe(0);
      expect(REASON_CODES[code].scoring, code).toBe(false);
    }
  });

  it("form codes keep their weights", () => {
    expect(REASON_CODES.ip_obfuscation.weight).toBe(0.4);
    expect(REASON_CODES.ambiguous_numeric_host.weight).toBe(0.3);
    expect(REASON_CODES.ssrf_cloud_metadata.weight).toBe(1);
    expect(REASON_CODES.ssrf_cloud_metadata.scoring).toBe(true);
  });

  it("WEIGHTS_VERSION 1.22 → 1.23", () => {
    expect(WEIGHTS_VERSION).toBe("1.23");
  });
});

describe("destination-membership codes — verdicts", () => {
  it("169.254.169.254 is reported, at 0.00/info by default", () => {
    const r = verdict("http://169.254.169.254/");
    expect(r.codes).toEqual(["ip_cloud_metadata"]);
    expect(r.weights.ip_cloud_metadata).toBe(0);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("169.254.169.254 still lands critical under agentMode, on ssrf_cloud_metadata alone", () => {
    const r = verdict("http://169.254.169.254/", { agentMode: true });
    expect(r.codes).toEqual(["ssrf_cloud_metadata", "ip_cloud_metadata"]);
    expect(r.weights).toEqual({ ssrf_cloud_metadata: 1, ip_cloud_metadata: 0 });
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
  });

  it("192.168.1.1 is reported, at 0.00/info", () => {
    const r = verdict("http://192.168.1.1/");
    expect(r.codes).toEqual(["ip_private"]);
    expect(r.weights.ip_private).toBe(0);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("2130706433 scores 0.40/medium, carried by the form code alone", () => {
    const r = verdict("http://2130706433/");
    expect(r.codes).toEqual(["ip_obfuscation", "ip_loopback"]);
    expect(r.weights).toEqual({ ip_obfuscation: 0.4, ip_loopback: 0 });
    expect(r.score).toBeCloseTo(0.4, 5);
    expect(r.severity).toBe("medium");
  });
});
