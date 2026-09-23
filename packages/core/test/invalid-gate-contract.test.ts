import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import type { InspectResult, Severity } from "../src/schema/types.js";

/**
 * LINK-ucuduzwp — the score contract for `status: "invalid"` results that carry
 * scoring-weight findings.
 *
 * A3 (LINK-ctkfbdkf) established the founding contract: unparseable input returns
 * `status: "invalid"`, `parsed: null`, `score: null`. That is deliberate and is
 * NOT changed here. The hazard is what a caller does with it.
 *
 * Structural scans run BEFORE parsing, so they emit real scoring weight on inputs
 * that then fail to parse — and that weight is discarded when the score goes
 * null. A caller gating on `score` therefore fails OPEN on exactly the inputs
 * that were interesting enough to trip a pre-parse scan.
 *
 * This suite pins BOTH halves of the contract, so neither can drift silently:
 * the naive gate really does fail open on these inputs (documented hazard), and
 * the recommended predicate really does not (documented remedy). See
 * docs/scoring.md § "Gating on results".
 */

const FULLWIDTH_STOP = "．";

/** The documented gate predicate from docs/scoring.md. Fails CLOSED. */
const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function shouldBlock(result: InspectResult, failOn: Severity = "high"): boolean {
  // Unparseable input is "not checked", never "checked and clean".
  if (result.status === "invalid") return true;
  return RANK[result.severity as Severity] >= RANK[failOn];
}

/** The gate a caller writes by reflex. Present ONLY to prove it is unsafe. */
function naiveGate(result: InspectResult, failOn = 0.5): boolean {
  return result.score !== null && result.score >= failOn;
}

// Both metadata spellings run under agentMode. Since LINK-bwqhvjcs the plain
// host reports `ip_cloud_metadata` at weight 0 by default (architecture
// §6.1.10), so the declared agent context — where `ssrf_cloud_metadata` scores
// 1.0 — is the one in which the plain spelling is blocked by a numeric gate.
const AGENT = { agentMode: true } as const;
const metadataPlain = inspect("http://169.254.169.254/", AGENT);
const metadataFullwidth = inspect(
  `http://169${FULLWIDTH_STOP}254${FULLWIDTH_STOP}169${FULLWIDTH_STOP}254/`,
  AGENT,
);
const obfuscatedLoopback = inspect("http://2130706433/");
const overSlashed = inspect("https:///evil.com");
const benign = inspect("https://github.com/");

describe("invalid results can carry real scoring weight", () => {
  it("the plain cloud-metadata host is ok and scores critical under agentMode", () => {
    expect(metadataPlain.status).toBe("ok");
    expect(metadataPlain.score).toBe(1);
    expect(metadataPlain.reasons.map((r) => r.code)).toEqual([
      "ssrf_cloud_metadata",
      "ip_cloud_metadata",
    ]);
  });

  it("the SAME host with fullwidth dots is invalid with a null score", () => {
    expect(metadataFullwidth.status).toBe("invalid");
    expect(metadataFullwidth.score).toBeNull();
    expect(metadataFullwidth.severity).toBeNull();
  });

  it("…yet it fired a weight-0.5 scoring reason that was discarded", () => {
    // This is the whole point: the finding is real and weighted, and the null
    // score throws it away. If separator_lookalike's weight ever drops to 0 this
    // fails, which is correct — the hazard would have changed shape.
    expect(metadataFullwidth.reasons.map((r) => r.code)).toContain("separator_lookalike");
    expect(REASON_CODES.separator_lookalike.weight).toBe(0.5);
  });

  it("an over-slashed authority discards weight 0.65 the same way", () => {
    expect(overSlashed.status).toBe("invalid");
    expect(overSlashed.score).toBeNull();
    expect(overSlashed.reasons.map((r) => r.code)).toContain("ambiguous_authority");
    expect(REASON_CODES.ambiguous_authority.weight).toBe(0.65);
  });
});

describe("the naive numeric gate FAILS OPEN (documented hazard)", () => {
  // Asserted, not merely described, so the docs cannot quietly go out of date.
  it("blocks the plain metadata host", () => {
    expect(naiveGate(metadataPlain)).toBe(true);
  });

  it("lets the fullwidth-dot metadata host through — same endpoint, not blocked", () => {
    expect(naiveGate(metadataFullwidth)).toBe(false);
  });

  it("lets the over-slashed authority through", () => {
    expect(naiveGate(overSlashed)).toBe(false);
  });
});

describe("the documented predicate does NOT fail open", () => {
  it.each([
    { name: "plain metadata host", result: metadataPlain },
    { name: "fullwidth-dot metadata host", result: metadataFullwidth },
    { name: "over-slashed authority", result: overSlashed },
  ])("blocks the $name", ({ result }) => {
    expect(shouldBlock(result)).toBe(true);
  });

  it("still lets an ordinary benign URL through (it is a gate, not a wall)", () => {
    expect(benign.status).toBe("ok");
    expect(benign.score).toBe(0);
    expect(shouldBlock(benign)).toBe(false);
  });

  it("respects the threshold for parsed results", () => {
    // 0.40 is `medium`: blocked at failOn "medium", allowed at "high".
    expect(obfuscatedLoopback.status).toBe("ok");
    expect(obfuscatedLoopback.score).toBeCloseTo(0.4, 5);
    expect(shouldBlock(obfuscatedLoopback, "medium")).toBe(true);
    expect(shouldBlock(obfuscatedLoopback, "high")).toBe(false);
    // …but an invalid result blocks at EVERY threshold, including "critical".
    expect(shouldBlock(metadataFullwidth, "critical")).toBe(true);
  });
});

describe("the A3 contract itself is unchanged", () => {
  it("every invalid result has null score AND null severity", () => {
    for (const result of [metadataFullwidth, overSlashed, inspect("https://")]) {
      expect(result.status).toBe("invalid");
      expect(result.score).toBeNull();
      expect(result.severity).toBeNull();
      expect(result.parsed).toBeNull();
    }
  });

  it("an invalid result still carries its provenance stamps", () => {
    // Reproducibility survives a parse failure — the caller can still tell which
    // data release produced the verdict.
    expect(metadataFullwidth.dataVersions).toBeDefined();
    expect(metadataFullwidth.pslSnapshot).toBeDefined();
    expect(metadataFullwidth.schemaVersion).toBe(metadataPlain.schemaVersion);
  });
});
