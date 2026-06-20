import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import type { InspectOptions } from "../src/index.js";

/**
 * H5 — cross-axis policy matrix. The per-axis files (policy-tld / policy-host /
 * policy-scheme-port) cover each axis in isolation; this file exercises
 * COMBINATIONS the per-axis files do not: multiple axes firing on one input,
 * stacked allow-mode lockdowns, and a fully-locked-down corporate policy passing
 * a legitimate input. Each case asserts the EXACT set of policy reason codes.
 *
 * `policyCodes` returns the sorted, deduped set of `layer: "policy"` codes so
 * the matrix is order-independent and deterministic.
 */
const policyCodes = (input: string, opts: InspectOptions): string[] =>
  [
    ...new Set(
      inspect(input, opts)
        .reasons.filter((r) => r.layer === "policy")
        .map((r) => r.code),
    ),
  ].sort();

const CASES: { name: string; input: string; opts: InspectOptions; expected: string[] }[] = [
  {
    name: "all four deny axes fire on one input",
    input: "ftp://evil.ru:8080/",
    opts: { denyTlds: ["ru"], denyHosts: ["evil.ru"], denySchemes: ["ftp"], denyPorts: [8080] },
    expected: ["host_denied", "port_denied", "scheme_denied", "tld_denied"],
  },
  {
    name: "stacked allow-mode lockdowns all miss on a non-conforming input",
    input: "https://promo.cn:9999/",
    opts: { allowTlds: ["com"], allowHosts: ["mycompany.com"], allowSchemes: ["https"], denyNonStandardPorts: true },
    expected: ["host_not_allowlisted", "port_denied", "tld_not_allowlisted"],
    // scheme is https → allow-list passes; port 9999 is non-standard for https → denied.
  },
  {
    name: "fully-locked-down corporate policy passes a legitimate input (zero policy reasons)",
    input: "https://app.mycompany.com/",
    opts: { allowTlds: ["com"], allowHosts: ["mycompany.com"], allowSchemes: ["https"] },
    expected: [],
  },
  {
    name: "deny TLD + scheme allow-list fire, but standard FTP port :21 is exempt under denyNonStandardPorts",
    input: "ftp://files.bad.ru:21/",
    opts: { denyTlds: ["ru"], allowSchemes: ["https"], denyNonStandardPorts: true },
    expected: ["scheme_denied", "tld_denied"],
  },
  {
    name: "deny + allow on the same axis both fire (independent axes)",
    input: "https://promo.ru/",
    opts: { denyTlds: ["ru"], allowTlds: ["com"], denyHosts: ["promo.ru"], allowHosts: ["mycompany.com"] },
    expected: ["host_denied", "host_not_allowlisted", "tld_denied", "tld_not_allowlisted"],
  },
];

describe("H5 policy — cross-axis matrix", () => {
  it.each(CASES)("$name", ({ input, opts, expected }) => {
    expect(policyCodes(input, opts)).toEqual(expected);
  });

  it("none of the matrix cases moves the deception score", () => {
    for (const { input, opts } of CASES) {
      expect(inspect(input, opts).score).toBe(inspect(input).score);
      expect(inspect(input, opts).severity).toBe(inspect(input).severity);
    }
  });
});
