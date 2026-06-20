import { describe, expect, it } from "vitest";
import { POLICY_AXIS_DESCRIPTORS } from "../src/policy/axes.js";
import { POLICY_OPTION_KEYS } from "../src/policy/options.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";

// Coverage invariants over the unified policy descriptor registry
// (POLICY_AXIS_DESCRIPTORS). These guard the code⇄axis⇄option-key wiring so it
// cannot silently drift from the REASON_CODES registry or the recognized-key
// list — mirroring the detector CHECKS registry guards in checks-registry.test.
// A policy code added without an axis, an axis wired to a non-policy code, or an
// option key dropped from the derivation all fail loudly here.

const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
const registryCodeSet = new Set<string>(registryCodes);

// The set of policy-layer codes in REASON_CODES, derived programmatically — never
// a hardcoded literal list — so the expected axis-owned set tracks the registry.
const policyOwnedCodes = registryCodes.filter(
  (code) => REASON_CODES[code].layer === "policy",
);

describe("POLICY_AXIS_DESCRIPTORS registry ⇄ REASON_CODES coverage invariants", () => {
  // 1. emits + optionKeys are valid + non-empty. Type-enforced at compile time,
  //    but a bad cast (`as ReasonCode`) would slip past tsc — assert at runtime.
  describe("every descriptor emits ≥1 valid reason code and has ≥1 option key", () => {
    it.each(POLICY_AXIS_DESCRIPTORS.map((d) => [d.id, d] as const))(
      "%s emits a non-empty list of real REASON_CODES keys",
      (_id, descriptor) => {
        expect(descriptor.emits.length).toBeGreaterThan(0);
        for (const code of descriptor.emits) {
          expect(registryCodeSet.has(code)).toBe(true);
        }
      },
    );

    it.each(POLICY_AXIS_DESCRIPTORS.map((d) => [d.id, d] as const))(
      "%s has a non-empty list of string option keys",
      (_id, descriptor) => {
        expect(descriptor.optionKeys.length).toBeGreaterThan(0);
        for (const key of descriptor.optionKeys) {
          expect(typeof key).toBe("string");
          expect((key as string).length).toBeGreaterThan(0);
        }
      },
    );
  });

  // 2. layer agreement: every emitted code's registry layer is "policy".
  describe("emitted code layer is policy", () => {
    it.each(POLICY_AXIS_DESCRIPTORS.map((d) => [d.id, d] as const))(
      "%s emits only policy-layer codes",
      (_id, descriptor) => {
        for (const code of descriptor.emits) {
          expect(REASON_CODES[code].layer).toBe("policy");
        }
      },
    );
  });

  // 3. uniqueness: distinct axis ids, each reason code owned by at most one axis,
  //    and no option key shared across descriptors.
  describe("uniqueness", () => {
    it("has no duplicate axis ids", () => {
      const ids = POLICY_AXIS_DESCRIPTORS.map((d) => d.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("has no duplicate emitted reason code across all descriptors", () => {
      const emitted = POLICY_AXIS_DESCRIPTORS.flatMap((d) => [...d.emits]);
      expect(new Set(emitted).size).toBe(emitted.length);
    });

    it("has no duplicate option key across all descriptors", () => {
      const keys = POLICY_AXIS_DESCRIPTORS.flatMap((d) => [...d.optionKeys]);
      expect(new Set(keys).size).toBe(keys.length);
    });
  });

  // 4. FORWARD + REVERSE coverage — the core drift guard. The set of all codes
  //    emitted by POLICY_AXIS_DESCRIPTORS must EQUAL exactly the set of
  //    policy-layer registry codes. Fails if someone adds a policy reason code
  //    without wiring an axis (REVERSE gap), wires a non-policy code (FORWARD gap
  //    — also caught by #1/#2), or removes an axis but leaves its code behind.
  describe("forward + reverse coverage against policy-owned codes", () => {
    const emittedCodes = new Set(
      POLICY_AXIS_DESCRIPTORS.flatMap((d) => [...d.emits]),
    );

    // FORWARD: every policy-layer registry code is emitted by some axis.
    it.each(policyOwnedCodes)("policy-owned code %s is emitted by an axis", (code) => {
      expect(emittedCodes.has(code)).toBe(true);
    });

    // REVERSE: every emitted code is a policy-layer registry code.
    it.each([...emittedCodes])("emitted code %s is a policy-owned registry code", (code) => {
      expect(policyOwnedCodes).toContain(code);
    });

    // Whole-set equality, so a simultaneous add+remove that keeps the count equal
    // is still caught.
    it("emitted set equals the policy-owned set exactly", () => {
      expect([...emittedCodes].sort()).toEqual([...policyOwnedCodes].sort());
    });
  });

  // 5. derivation guard: POLICY_OPTION_KEYS must equal the order-preserving
  //    flatMap of the descriptors' optionKeys. Locks the options.ts derivation so
  //    the recognized-key list cannot drift from the registry.
  describe("POLICY_OPTION_KEYS derivation", () => {
    it("equals the order-preserving flatMap of descriptor optionKeys", () => {
      const expected = POLICY_AXIS_DESCRIPTORS.flatMap((d) => [...d.optionKeys]);
      expect([...POLICY_OPTION_KEYS]).toEqual(expected);
    });
  });
});
