import { describe, expect, it } from "vitest";
import { CHECKS } from "../src/detectors/checks.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";

// Coverage invariants over the unified descriptor registry (CHECKS). These guard
// the code⇄detector wiring so it cannot silently drift from the REASON_CODES
// registry: a reason code added without a detector, a detector wired to a wrong-
// layer code, or a detector removed but its code left behind all fail loudly here.

const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
const registryCodeSet = new Set<string>(registryCodes);

// The reason codes that are emitted OUTSIDE the check registry, so the FORWARD +
// REVERSE coverage invariant must NOT expect a detector to own them:
//   • policy-layer codes (tld_denied, host_denied, scheme_denied, …) are produced
//     by the caller-configured policy channel, not by any detector in CHECKS.
//   • `parse_error` is a lexical META code emitted on the invalid/unparseable path
//     (when there is no URL to run detectors over), not by any check.
// Derived programmatically from REASON_CODES — never a hardcoded literal list — so
// the expected detector-owned set tracks the registry automatically.
const detectorOwnedCodes = registryCodes.filter(
  (code) => REASON_CODES[code].layer !== "policy" && code !== "parse_error",
);

describe("CHECKS registry ⇄ REASON_CODES coverage invariants", () => {
  // 1. emits are valid + non-empty. Type-enforced at compile time, but a bad cast
  //    (`as ReasonCode`) would slip past tsc — assert at runtime so it is caught.
  describe("every descriptor emits ≥1 valid reason code", () => {
    it.each(CHECKS.map((c) => [c.id, c] as const))(
      "%s emits a non-empty list of real REASON_CODES keys",
      (_id, check) => {
        expect(check.emits.length).toBeGreaterThan(0);
        for (const code of check.emits) {
          expect(registryCodeSet.has(code)).toBe(true);
        }
      },
    );
  });

  // 2. layer agreement: each emitted code's registry layer matches the descriptor's
  //    layer. Catches wiring a policy/wrong-layer code onto a lexical check.
  describe("emitted code layer matches the descriptor layer", () => {
    it.each(CHECKS.map((c) => [c.id, c] as const))(
      "%s emits only codes whose registry layer matches",
      (_id, check) => {
        for (const code of check.emits) {
          expect(REASON_CODES[code].layer).toBe(check.layer);
        }
      },
    );
  });

  // 3. phase/layer sanity: shape of the registry itself.
  describe("registry phase/layer shape", () => {
    it("contains exactly 37 checks", () => {
      expect(CHECKS.length).toBe(37);
    });

    it("splits into 4 structural-phase + 33 parsed-phase descriptors", () => {
      const structural = CHECKS.filter((c) => c.phase === "structural");
      const parsed = CHECKS.filter((c) => c.phase === "parsed");
      expect(structural.length).toBe(4);
      expect(parsed.length).toBe(33);
    });

    it("has every structural-phase descriptor on the lexical layer", () => {
      const structural = CHECKS.filter((c) => c.phase === "structural");
      for (const check of structural) {
        expect(check.layer).toBe("lexical");
      }
    });
  });

  // 4. uniqueness: each check has a distinct id, and each reason code is owned by
  //    at most one check (no code emitted by two descriptors).
  describe("uniqueness", () => {
    it("has no duplicate check ids", () => {
      const ids = CHECKS.map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("has no duplicate emitted reason code across all descriptors", () => {
      const emitted = CHECKS.flatMap((c) => [...c.emits]);
      expect(new Set(emitted).size).toBe(emitted.length);
    });
  });

  // 5. FORWARD + REVERSE coverage — the core drift guard. The set of all codes
  //    emitted by CHECKS must EQUAL exactly the set of detector-owned registry
  //    codes (every lexical code except the `parse_error` meta code). This fails if
  //    someone adds a reason code without wiring a detector (REVERSE gap), wires a
  //    code with no registry entry (FORWARD gap — also caught by #1), or removes a
  //    detector but leaves its code in the registry.
  describe("forward + reverse coverage against detector-owned codes", () => {
    const emittedCodes = new Set(CHECKS.flatMap((c) => [...c.emits]));

    // FORWARD: every detector-owned registry code is emitted by some check.
    it.each(detectorOwnedCodes)("detector-owned code %s is emitted by a check", (code) => {
      expect(emittedCodes.has(code)).toBe(true);
    });

    // REVERSE: every emitted code is a detector-owned registry code (i.e. no check
    // emits a policy code or the parse_error meta code).
    it.each([...emittedCodes])("emitted code %s is a detector-owned registry code", (code) => {
      expect(detectorOwnedCodes).toContain(code);
    });

    // Whole-set equality, so a simultaneous add+remove that keeps the count equal
    // is still caught.
    it("emitted set equals the detector-owned set exactly", () => {
      expect([...emittedCodes].sort()).toEqual([...detectorOwnedCodes].sort());
    });
  });

  // 6. skipReportable: documents the current contract — every check records a
  //    runtime failure in `checksSkipped`. A future intentional exception updates
  //    this assertion.
  describe("skipReportable contract", () => {
    it.each(CHECKS.map((c) => [c.id, c] as const))(
      "%s has skipReportable === true",
      (_id, check) => {
        expect(check.skipReportable).toBe(true);
      },
    );
  });
});
