import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { normalizeOptions, normalizePolicyOptions } from "../src/parse/runtime.js";

/**
 * The TRIM CLASS (LINK-uxkrtcnw → LINK-stuiljry → LINK-qajalduf).
 *
 * MR !41 put the surrounding-whitespace trim inside `normalizedList` — the
 * single choke point every POLICY axis routes through — precisely so a future
 * axis would inherit it by construction. Two list-valued options never routed
 * through that choke point and so never inherited it: `idnAllowlist` and
 * `suppressReasons`. Both are caller-supplied EXEMPTIONS, so a padded value is
 * silently void: no error, no warning, and the caller believes an escape hatch
 * is in force when it is not.
 *
 * This file is the class-level pin. It asserts BOTH halves of the enumeration —
 * the seven options that do route through `normalizedList`, and the two that do
 * not — so the choke point cannot be emptied out from under the policy axes and
 * a third option cannot silently join the untrimmed side.
 */

const codes = (input: string, opts?: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.map((r) => r.code);

const suppressed = (input: string, opts: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.filter((r) => r.suppressed === true).map((r) => r.code);

// ── The routed side: every option that goes through normalizedList ───────────
// Held here as well as in policy-runtime.test.ts because the claim under test
// is about the CHOKE POINT, not about any one axis: emptying the trim out of
// normalizedList must fail this block.
describe("list options that route through normalizedList — trim inherited", () => {
  it("trims every string policy axis", () => {
    const policy = normalizePolicyOptions({
      denyTlds: [" ru"],
      allowTlds: ["com "],
      denyHosts: [" evil.com "],
      allowHosts: ["\tmycompany.com"],
      denySchemes: [" javascript"],
      allowSchemes: ["https\n"],
    });

    expect(policy.denyTlds.set.has("ru")).toBe(true);
    expect(policy.allowTlds.set.has("com")).toBe(true);
    expect(policy.denyHosts.set.has("evil.com")).toBe(true);
    expect(policy.allowHosts.set.has("mycompany.com")).toBe(true);
    expect(policy.denySchemes.set.has("javascript")).toBe(true);
    expect(policy.allowSchemes.set.has("https")).toBe(true);
  });

  it("leaves the numeric axis alone — a trim has nothing to do to a number", () => {
    const policy = normalizePolicyOptions({ denyPorts: [8080] });
    expect(policy.denyPorts.set.has(8080)).toBe(true);
  });
});

// ── The unrouted side: PINNED AS THE FAIL-OPEN IT IS ─────────────────────────
// LINK-qajalduf. Each `expect` below records behaviour that is WRONG. The fix
// inverts this block; it is here first so the fix has to move it deliberately
// rather than by accident.
describe("idnAllowlist — untrimmed entries (pinned fail-open)", () => {
  it("a padded entry does not exempt: idn_host still fires", () => {
    expect(codes("https://münchen.de", { idnAllowlist: [" münchen.de"] })).toContain("idn_host");
    expect(codes("https://münchen.de", { idnAllowlist: ["münchen.de "] })).toContain("idn_host");
  });

  it("leading whitespace defeats the leading-dot strip", () => {
    expect(codes("https://münchen.de", { idnAllowlist: [" .münchen.de"] })).toContain("idn_host");
  });

  it("splitting a config string on ',' voids every entry after the first", () => {
    const allow = "köln.de, münchen.de".split(",");
    expect(codes("https://köln.de", { idnAllowlist: allow })).not.toContain("idn_host");
    expect(codes("https://münchen.de", { idnAllowlist: allow })).toContain("idn_host");
  });

  it("the padded entry survives into the runtime set as a dead member", () => {
    const runtime = normalizeOptions({ idnAllowlist: [" münchen.de", "  "] });
    expect(runtime.idnAllowlist.has(" münchen.de")).toBe(true);
    expect(runtime.idnAllowlist.has("münchen.de")).toBe(false);
    expect(runtime.idnAllowlist.has("  ")).toBe(true);
  });

  it("the exemption still fails OPEN silently — no error, no skipped token", () => {
    const r = inspect("https://münchen.de", { idnAllowlist: [" münchen.de"] });
    expect(r.checksSkipped).not.toContain("options:idnAllowlist");
    expect(r.severity).toBe("high");
  });
});

// LINK-qajalduf, found by the enumeration this unit was asked to run:
// `suppressReasons` is the NINTH list-valued option and it is defective the
// same way, on BOTH of its caller-supplied strings.
describe("suppressReasons — untrimmed entries (pinned fail-open)", () => {
  it("a padded host does not scope: the reason is never suppressed", () => {
    const rule = { code: "idn_host", host: " münchen.de" } as const;
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toEqual([]);
    expect(inspect("https://münchen.de", { suppressReasons: [rule] }).score).toBeCloseTo(0.7, 5);
  });

  it("leading whitespace defeats the host's leading-dot strip", () => {
    const rule = { code: "idn_host", host: " .münchen.de" } as const;
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toEqual([]);
  });

  it("a padded code matches no reason", () => {
    const rule = { code: " idn_host" } as unknown as { code: "idn_host" };
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toEqual([]);
  });

  it("the padded strings survive into the runtime rules", () => {
    const runtime = normalizeOptions({
      suppressReasons: [{ code: "idn_host", host: " münchen.de" }],
    });
    expect(runtime.suppressReasons).toEqual([{ code: "idn_host", host: " münchen.de" }]);
  });

  it("the suppression still fails silently — the honesty marker claims it ran", () => {
    const r = inspect("https://münchen.de", {
      suppressReasons: [{ code: "idn_host", host: " münchen.de" }],
    });
    expect(r.checksRun).toContain("suppression");
    expect(r.reasons.some((x) => x.suppressed === true)).toBe(false);
  });
});
