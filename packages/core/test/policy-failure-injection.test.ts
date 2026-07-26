import { afterEach, describe, expect, it, vi } from "vitest";
import { inspect } from "../src/index.js";
import { POLICY_AXIS_DESCRIPTORS } from "../src/policy/axes.js";
import type { InspectOptions } from "../src/schema/types.js";

/**
 * LINK-voqqhxgj — the FR-D-13 catch on the policy channel, executed.
 *
 * `inspect()` has THREE FR-D-13 catch sites. The structural and parsed-detector
 * loops are exercised by `detector-failure-injection.test.ts`; the policy
 * channel was the one left unreachable, and this suite closes it.
 *
 * WHY IT WAS UNREACHABLE, and what changed:
 *
 * `policy.ts` used to derive its run list at module load —
 * `POLICY_AXIS_DESCRIPTORS.map((d) => d.run)` — which snapshots each `run`
 * reference the first time the module is imported. Spying on a descriptor
 * afterwards had no effect, because the snapshotted array already held the
 * original function; spying on the axis modules' exports failed for the same
 * reason one level up. The array itself was module-private, so a test could not
 * patch it either. `runPolicy` now resolves `descriptor.run` per call, which is
 * the same shape `DETECTORS` and `STRUCTURAL_SCANS` already had.
 *
 * Malformed options do not reach the catch either — measured, not assumed. The
 * axes are defensive, so a plain-JS caller passing wrong-typed policy config is
 * handled rather than thrown on. That is pinned below, because it is a real
 * guarantee and not merely the reason this suite has to inject failures.
 *
 * The spy targets the REAL registry object, not a module mock, so `inspect()`'s
 * own policy wiring stays under test rather than being replaced by the test.
 */

/** A URL that violates every axis, so each one has findings to lose. */
const VIOLATING_URL = "http://evil.example.zip:8443/";

/**
 * Policy config that arms all four axes against {@link VIOLATING_URL}. Note the
 * host entry is the REGISTRABLE DOMAIN, not the full host — the host axis
 * matches on eTLD+1 by design, so `example.zip` is what covers
 * `evil.example.zip`.
 */
const ALL_AXES_CONFIGURED: InspectOptions = {
  denyTlds: ["zip"],
  denyHosts: ["example.zip"],
  denySchemes: ["http"],
  denyPorts: [8443],
};

afterEach(() => {
  vi.restoreAllMocks();
});

/** Make one axis throw, addressed by its registry id. */
function breakAxis(id: string): void {
  const descriptor = POLICY_AXIS_DESCRIPTORS.find((d) => d.id === id);
  if (!descriptor) throw new Error(`no policy axis with id ${id}`);
  vi.spyOn(descriptor, "run").mockImplementation(() => {
    throw new Error(`injected failure in policy axis ${id}`);
  });
}

describe("the policy channel is spyable at all (LINK-voqqhxgj)", () => {
  it("resolves each axis's run from the registry on every call", () => {
    // The regression guard for the whole fix. If runPolicy ever goes back to
    // snapshotting at module load, the spy stops being observed and this fails
    // — which is the ONLY thing keeping the other tests in this file honest.
    const tld = POLICY_AXIS_DESCRIPTORS.find((d) => d.id === "tld")!;
    const spy = vi.spyOn(tld, "run").mockReturnValue([]);

    inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });

    expect(spy).toHaveBeenCalled();
  });

  it("sees a spy installed AFTER the module was first imported", () => {
    // Stronger than the above: this module has already been imported and
    // runPolicy already called by the time this runs, so a snapshot would
    // certainly exist by now.
    const port = POLICY_AXIS_DESCRIPTORS.find((d) => d.id === "port")!;
    const sentinel = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });
    expect(sentinel.reasons.map((r) => r.code)).toContain("port_denied");

    vi.spyOn(port, "run").mockReturnValue([]);
    const after = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });
    expect(after.reasons.map((r) => r.code)).not.toContain("port_denied");
  });
});

describe.each(POLICY_AXIS_DESCRIPTORS.map((d) => d.id))(
  "a throwing policy axis is contained (LINK-voqqhxgj): %s",
  (id) => {
    it("does not propagate out of inspect()", () => {
      breakAxis(id);
      expect(() => inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED })).not.toThrow();
    });

    it("still returns a scored, schema-valid result", () => {
      breakAxis(id);
      const result = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });

      // Policy findings are weight 0, so losing them must not move the score —
      // the lexical verdict is unaffected by a policy failure.
      expect(result.status).toBe("ok");
      expect(result.score).not.toBeNull();
      expect(result.severity).not.toBeNull();
    });

    it("records the skip rather than swallowing it", () => {
      breakAxis(id);
      const result = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });

      // The honesty requirement of FR-D-13: a silent swallow would report a
      // clean policy verdict on input whose policy verdict was never computed.
      expect(result.checksSkipped).toContain("policy");
    });

    it("loses the whole channel, not just the failing axis", () => {
      breakAxis(id);
      const result = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });

      // Documenting real behavior, not endorsing it: the catch wraps the whole
      // runPolicy() call, so one bad axis costs all four. Findings from axes
      // that already ran are discarded with it. Making the catch per-axis is a
      // deliberate follow-up (see the issue), not something to change silently.
      const codes = result.reasons.map((r) => r.code);
      expect(codes).not.toContain("tld_denied");
      expect(codes).not.toContain("host_denied");
      expect(codes).not.toContain("scheme_denied");
      expect(codes).not.toContain("port_denied");
    });
  },
);

describe("the undisturbed policy channel (LINK-voqqhxgj)", () => {
  it("emits every axis's finding when nothing is broken", () => {
    // The control. Without this, all four assertions above would still pass if
    // the policy channel silently stopped running altogether.
    const result = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });

    expect(result.checksSkipped).not.toContain("policy");
    expect(result.checksRun).toContain("policy");
    expect(result.reasons.map((r) => r.code)).toEqual(
      expect.arrayContaining(["tld_denied", "host_denied", "scheme_denied", "port_denied"]),
    );
  });

  it("orders policy reasons deterministically, by code", () => {
    // NOT registry order. `runPolicy` concatenates in registry order (TLD →
    // host → scheme → port), but serialize sorts every reason by weight desc
    // then code asc, and all policy findings are weight 0 — so what a caller
    // observes is alphabetical, and the registry order is invisible here.
    //
    // Asserting registry order at this level would be inventing a contract the
    // code does not have. The real guarantee, and the one worth pinning, is
    // that the output order is stable and locale-independent.
    const result = inspect(VIOLATING_URL, { ...ALL_AXES_CONFIGURED });
    const policyCodes = result.reasons
      .filter((r) => r.layer === "policy")
      .map((r) => r.code);

    expect(policyCodes).toEqual([
      "host_denied",
      "port_denied",
      "scheme_denied",
      "tld_denied",
    ]);
  });

  it("stays byte-identical when no policy is configured", () => {
    // The fix must be a pure refactor for the overwhelmingly common caller who
    // configures no policy at all.
    const result = inspect(VIOLATING_URL);
    expect(result.checksRun).not.toContain("policy");
    expect(result.checksSkipped).not.toContain("policy");
    expect(result.reasons.every((r) => r.layer !== "policy")).toBe(true);
  });
});

describe("malformed policy options do not reach the catch (LINK-voqqhxgj)", () => {
  // The axes are defensive by design. A plain-JS caller passing wrong-typed
  // config gets a handled result, NOT a skipped channel — so `checksSkipped`
  // stays clean and the never-throws guarantee holds without the backstop.
  const MALFORMED: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ["denyTlds as a number", { denyTlds: 123 }],
    ["denyHosts as a bare string", { denyHosts: "evil.com" }],
    ["allowSchemes as null", { allowSchemes: null }],
    ["denyTlds as an object", { denyTlds: {} }],
  ];

  it.each(MALFORMED)("is handled, not caught: %s", (_label, options) => {
    const result = inspect(VIOLATING_URL, options as never);

    expect(result.status).toBe("ok");
    expect(result.checksSkipped).not.toContain("policy");
  });
});
