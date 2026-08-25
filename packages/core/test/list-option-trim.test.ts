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

// ── The formerly-unrouted side: FIXED ────────────────────────────────────────
// LINK-qajalduf. `idnAllowlist` now routes through normalizedList; each `it`
// below was pinned in the previous commit asserting the opposite.
describe("idnAllowlist — trimmed entries", () => {
  it("a padded entry exempts, exactly as an unpadded one does", () => {
    expect(codes("https://münchen.de", { idnAllowlist: [" münchen.de"] })).not.toContain(
      "idn_host",
    );
    expect(codes("https://münchen.de", { idnAllowlist: ["münchen.de "] })).not.toContain(
      "idn_host",
    );
    expect(codes("https://münchen.de", { idnAllowlist: ["\tmünchen.de\n"] })).not.toContain(
      "idn_host",
    );
  });

  it("the trim runs BEFORE the leading-dot strip, so ' .x' still works", () => {
    expect(codes("https://münchen.de", { idnAllowlist: [" .münchen.de"] })).not.toContain(
      "idn_host",
    );
  });

  it("splitting a config string on ',' now exempts every entry", () => {
    const allow = "köln.de, münchen.de".split(",");
    expect(codes("https://köln.de", { idnAllowlist: allow })).not.toContain("idn_host");
    expect(codes("https://münchen.de", { idnAllowlist: allow })).not.toContain("idn_host");
  });

  it("still exempts across Unicode/punycode presentations after trimming", () => {
    expect(codes("https://xn--mnchen-3ya.de/", { idnAllowlist: [" münchen.de "] })).not.toContain(
      "idn_host",
    );
    expect(codes("https://münchen.de", { idnAllowlist: [" xn--mnchen-3ya.de "] })).not.toContain(
      "idn_host",
    );
  });

  it("an unlisted IDN is still blocked — the trim widens nothing", () => {
    expect(codes("https://köln.de", { idnAllowlist: [" münchen.de"] })).toContain("idn_host");
  });

  it("drops an entry that is empty after trimming, keeping its neighbours", () => {
    const runtime = normalizeOptions({ idnAllowlist: ["  ", "münchen.de", "", "."] });
    expect(runtime.idnAllowlist.has("münchen.de")).toBe(true);
    expect(runtime.idnAllowlist.has("")).toBe(false);
    expect(runtime.idnAllowlist.has("  ")).toBe(false);
    expect(runtime.idnAllowlist.size).toBe(1);
  });

  // Dropping is fail-CLOSED here for a simpler reason than on the policy
  // allow-lists: idnAllowlist is an EXEMPTION list, so an emptied one exempts
  // nothing and every IDN keeps emitting idn_host.
  it("an all-blank allow-list exempts nothing, so it fails CLOSED", () => {
    expect(codes("https://münchen.de", { idnAllowlist: ["  "] })).toContain("idn_host");
    expect(inspect("https://münchen.de", { idnAllowlist: ["  "] }).severity).toBe("high");
  });

  it("non-string entries are still dropped without throwing", () => {
    const runtime = normalizeOptions({
      idnAllowlist: [null, 42, { }, " münchen.de"] as unknown as string[],
    });
    expect([...runtime.idnAllowlist]).toEqual(["münchen.de"]);
  });
});

// LINK-qajalduf, found by the enumeration this unit was asked to run:
// `suppressReasons` is the NINTH list-valued option and was defective the same
// way, on BOTH of its caller-supplied strings. It cannot route through
// normalizedList (its entries are objects), so it applies the same
// `trimListValue` to its inner fields instead.
describe("suppressReasons — trimmed entries", () => {
  it("a padded host scopes correctly: the reason is suppressed", () => {
    const rule = { code: "idn_host", host: " münchen.de" } as const;
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toContain("idn_host");
    expect(inspect("https://münchen.de", { suppressReasons: [rule] }).score).toBe(0);
  });

  it("the trim runs BEFORE the host's leading-dot strip", () => {
    const rule = { code: "idn_host", host: " .münchen.de" } as const;
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toContain("idn_host");
  });

  it("a padded code matches its reason", () => {
    const rule = { code: " idn_host " } as unknown as { code: "idn_host" };
    expect(suppressed("https://münchen.de", { suppressReasons: [rule] })).toContain("idn_host");
  });

  it("a host-scoped rule still does not leak to another host", () => {
    const rule = { code: "idn_host", host: " münchen.de" } as const;
    expect(suppressed("https://köln.de", { suppressReasons: [rule] })).toEqual([]);
  });

  it("a rule whose code is blank after trimming is dropped", () => {
    const runtime = normalizeOptions({
      suppressReasons: [{ code: "  " }, { code: " idn_host" }] as never,
    });
    expect(runtime.suppressReasons).toEqual([{ code: "idn_host", host: null }]);
  });

  // The honesty marker reads the RAW option, never the normalized length, so
  // dropping a rule cannot hide that an escape hatch was wired.
  it("dropping every rule still reports the suppression channel in checksRun", () => {
    const r = inspect("https://münchen.de", { suppressReasons: [{ code: "  " }] as never });
    expect(r.checksRun).toContain("suppression");
    expect(r.reasons.some((x) => x.suppressed === true)).toBe(false);
  });

  // A blank host means "all hosts" — the documented shape of a global rule,
  // unchanged by this fix. A host that CANONICALIZES to "" must not collapse to
  // null, which would silently widen the rule to every host.
  it("a blank host is still a global rule; a '.' host is a dead scope", () => {
    const runtime = normalizeOptions({
      suppressReasons: [
        { code: "idn_host", host: "  " },
        { code: "mixed_script", host: " . " },
      ],
    });
    expect(runtime.suppressReasons).toEqual([
      { code: "idn_host", host: null },
      { code: "mixed_script", host: "" },
    ]);
    expect(suppressed("https://köln.de", { suppressReasons: [{ code: "idn_host", host: "  " }] }))
      .toContain("idn_host");
  });
});
