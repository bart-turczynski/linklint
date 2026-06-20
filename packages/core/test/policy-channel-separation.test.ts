import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import type { InspectOptions, Reason } from "../src/index.js";

/**
 * H5 — the epic's headline guarantee: the policy channel is a SEPARATE channel
 * from deception detection. Configuring an aggressively-matching policy may add
 * `layer: "policy"` reasons and put "policy" in `checksRun`, but it must NEVER
 * change `score`, `severity`, or any non-policy reason.
 *
 * Each case carries an `aggressive` policy hand-built to force every applicable
 * axis to fire for that input (deny its TLD, deny its registrable domain,
 * allow-list a scheme it does not have, deny non-standard ports). The exact set
 * of policy codes is asserted in policy-matrix.test.ts; here we assert only the
 * invariant — what policy may and may not touch.
 */
const CASES: { input: string; aggressive: InspectOptions }[] = [
  {
    // benign
    input: "https://www.example.com/",
    aggressive: {
      denyTlds: ["com"],
      denyHosts: ["example.com"],
      allowSchemes: ["nonexistent"],
      denyNonStandardPorts: true,
    },
  },
  {
    // info-only (IDN normalization_delta)
    input: "https://bücher.de",
    aggressive: {
      denyTlds: ["de"],
      denyHosts: ["bücher.de"],
      allowSchemes: ["ftp"],
    },
  },
  {
    // deceptive — userinfo authority spoof (score 0.5 / medium)
    input: "https://paypal.com@evil.ru/",
    aggressive: {
      denyTlds: ["ru"],
      denyHosts: ["evil.ru"],
      allowSchemes: ["nonexistent"],
    },
  },
  {
    // deceptive — dangerous scheme (score 0.9 / critical), no host/TLD
    input: "javascript:alert(1)",
    aggressive: {
      denySchemes: ["javascript"],
      denyTlds: ["com"],
      denyHosts: ["example.com"],
    },
  },
];

const nonPolicy = (reasons: Reason[]) => reasons.filter((r) => r.layer !== "policy");

describe("H5 policy — channel-separation invariant", () => {
  it.each(CASES)("policy never moves score/severity/non-policy reasons: $input", ({ input, aggressive }) => {
    const base = inspect(input);
    const withPolicy = inspect(input, aggressive);

    // Score and severity are byte-identical regardless of policy.
    expect(withPolicy.score).toBe(base.score);
    expect(withPolicy.severity).toBe(base.severity);

    // The non-policy reasons are identical: same codes, same order, same weights.
    expect(nonPolicy(withPolicy.reasons)).toEqual(base.reasons);
    // ...and the baseline had no policy reasons at all to begin with.
    expect(base.reasons.every((r) => r.layer !== "policy")).toBe(true);

    // The only added reasons all live in the policy layer with weight 0.
    const added = withPolicy.reasons.filter(
      (r) => !base.reasons.some((b) => b.code === r.code && b.detail === r.detail),
    );
    expect(added.length).toBeGreaterThan(0);
    for (const r of added) {
      expect(r.layer).toBe("policy");
      expect(r.weight).toBe(0);
    }

    // checksRun gains exactly "policy" and nothing else.
    expect(base.checksRun).toEqual(["lexical"]);
    expect(withPolicy.checksRun).toEqual(["lexical", "policy"]);
    expect(withPolicy.checksSkipped).toEqual(base.checksSkipped);
  });

  it.each(CASES)("with no policy options the result is deep-equal to today: $input", ({ input }) => {
    // Passing no options and passing an empty options object must both be
    // byte-identical to the historical no-policy result.
    const noOpts = inspect(input);
    const emptyOpts = inspect(input, {});

    expect(emptyOpts).toEqual(noOpts);
    expect(noOpts.checksRun).toEqual(["lexical"]);
    expect(noOpts.reasons.some((r) => r.layer === "policy")).toBe(false);
  });
});
