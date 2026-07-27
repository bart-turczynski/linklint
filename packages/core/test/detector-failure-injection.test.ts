import { afterEach, describe, expect, it, vi } from "vitest";
import { inspect } from "../src/inspect.js";
import { DETECTORS } from "../src/detectors/registry.js";
import { STRUCTURAL_SCANS } from "../src/detectors/structural.js";

/**
 * FR-D-13 failure injection — the skip channel, executed.
 *
 * `inspect()` wraps every structural scan and every parsed detector in its own
 * try/catch and pushes `lexical:<id>` into `checksSkipped` when one throws. The
 * documented guarantee is that a detector failure **degrades** the inspection to
 * a lower bound rather than aborting it. Before this file, no test in the repo
 * ever made a check throw, so the entire channel was unexecuted
 * (`LINK-gnoipmcq`, and the third acceptance bullet of `LINK-hastsuzd`).
 *
 * That is the exact shape of `LINK-gqqrwrpk`, where `createNodeSafeTransport`
 * had zero behavioural coverage and turned out to be dead in production: an
 * unexercised guard is silent by construction — nothing fails, so nothing
 * notices.
 *
 * ── Injection technique ────────────────────────────────────────────────────
 * We spy on the `run` method of the REAL registry entry rather than mocking the
 * registry module. That keeps `inspect()`'s own wiring — registry iteration,
 * skip-list seeding, serialization — under test; a module mock would replace
 * the very code path the issue says is unproven. `vi.restoreAllMocks()` in
 * `afterEach` puts the shared registry object back, so ordering with other
 * suites cannot leak.
 */

/** Make the named parsed detector throw for the duration of one test. */
function breakDetector(id: string): void {
  const detector = DETECTORS.find((d) => d.id === id);
  expect(detector, `no such detector: ${id}`).toBeDefined();
  vi.spyOn(detector!, "run").mockImplementation(() => {
    throw new Error(`injected failure in ${id}`);
  });
}

/** Make the named structural scan throw for the duration of one test. */
function breakScan(id: string): void {
  const scan = STRUCTURAL_SCANS.find((s) => s.id === id);
  expect(scan, `no such structural scan: ${id}`).toBeDefined();
  vi.spyOn(scan!, "run").mockImplementation(() => {
    throw new Error(`injected failure in ${id}`);
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a parsed detector that throws is skipped, not fatal", () => {
  // `brand_lookalike` is the check that emits `brand_homoglyph` — the reason a
  // reader most often looks up. Baseline: 0.60 from brand_homoglyph (0.50) and
  // ascii_homoglyph (0.20) under probabilistic OR.
  const URL = "https://paypa1.com/";

  it("baseline: both reasons present at 0.60", () => {
    const r = inspect(URL);
    expect(r.status).toBe("ok");
    expect(r.score).toBeCloseTo(0.6, 5);
    expect(r.reasons.map((x) => x.code).sort()).toEqual(["ascii_homoglyph", "brand_homoglyph"]);
    expect(r.checksSkipped).not.toContain("lexical:brand_lookalike");
  });

  it("records lexical:<id> and still returns a usable result", () => {
    breakDetector("brand_lookalike");
    const r = inspect(URL);

    expect(r.status).toBe("ok");
    expect(r.checksSkipped).toContain("lexical:brand_lookalike");
  });

  it("degrades the score to a lower bound instead of aborting", () => {
    breakDetector("brand_lookalike");
    const r = inspect(URL);

    // THE DOCUMENTED CONSEQUENCE. The lost detector's weight is simply absent,
    // so the surviving signal alone sets the score: 0.60 -> 0.20. The result is
    // a lower bound, and `checksSkipped` is the only thing that says so — which
    // is exactly why a fail-closed consumer must read it.
    expect(r.score).toBeCloseTo(0.2, 5);
    expect(r.severity).toBe("low");
  });

  it("keeps every other detector's findings", () => {
    breakDetector("brand_lookalike");
    const r = inspect(URL);

    // Degrade, not abort: the neighbouring detector still reported.
    expect(r.reasons.map((x) => x.code)).toEqual(["ascii_homoglyph"]);
  });
});

describe("a structural scan that throws is skipped, not fatal", () => {
  // `control_char` is a STRUCTURAL scan (it runs before parse), so it exercises
  // the other call site — the one seeded into `skippedDetectors` ahead of the
  // parsed-detector loop.
  const URL = "https://user:pw@evil.com/a%00b";

  it("baseline: control_char contributes at 0.87", () => {
    const r = inspect(URL);
    expect(r.score).toBeCloseTo(0.87, 5);
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
  });

  it("records lexical:<scan id> on the ok path and drops only its finding", () => {
    breakScan("control_char");
    const r = inspect(URL);

    expect(r.status).toBe("ok");
    expect(r.checksSkipped).toContain("lexical:control_char");
    expect(r.reasons.map((x) => x.code)).not.toContain("control_char");
    // The two surviving reasons still score: 1 - (1-0.5)(1-0.35) = 0.675.
    expect(r.score).toBeCloseTo(0.675, 5);
    expect(r.reasons.map((x) => x.code).sort()).toEqual([
      "encoding_obfuscation",
      "userinfo_present",
    ]);
  });

  it("orders structural skips before parsed-detector skips", () => {
    // The shape is load-bearing: inspect() seeds skippedDetectors with the
    // structural list, then appends parsed-detector failures. Pin it so a
    // refactor that reorders the two loops is visible.
    breakScan("control_char");
    breakDetector("userinfo_present");
    const r = inspect(URL);

    const lexicalSkips = r.checksSkipped.filter((s) => s.startsWith("lexical:"));
    expect(lexicalSkips).toEqual(["lexical:control_char", "lexical:userinfo_present"]);
  });
});

describe("the never-throws guarantee holds when EVERY check fails", () => {
  // The worst case the channel exists for. If the skip machinery itself can
  // throw, this is where it shows.
  const URL = "https://user:pw@xn--pypal-4ve.com/a%00b?next=https://evil.com";

  // An agent-gated detector is `continue`d before its try/catch when agentMode
  // is off, so it CANNOT throw and must not appear in checksSkipped. That is the
  // documented distinction between "an available-but-disabled feature channel"
  // and "a check that was skipped" (serialize.ts), and it is the reason the
  // counts below are split rather than just `DETECTORS.length`.
  const gated = DETECTORS.filter((d) => d.agentGated === true);
  const ungated = DETECTORS.filter((d) => d.agentGated !== true);

  it("total detector failure still returns a well-formed ok result", () => {
    for (const d of DETECTORS) breakDetector(d.id);

    let r: ReturnType<typeof inspect>;
    expect(() => {
      r = inspect(URL);
    }).not.toThrow();

    r = inspect(URL);
    expect(r.status).toBe("ok");
    // Every non-gated detector is named...
    for (const d of ungated) expect(r.checksSkipped).toContain(`lexical:${d.id}`);
    // ...and no gated one is, even though its run() was rigged to throw: it was
    // never reached. A disabled channel is not a skipped check.
    expect(gated.length).toBeGreaterThan(0);
    for (const d of gated) expect(r.checksSkipped).not.toContain(`lexical:${d.id}`);
    expect(r.score).not.toBeNull();
    expect(r.severity).not.toBeNull();
  });

  it("under agentMode the gated detectors fail into the same channel", () => {
    for (const d of DETECTORS) breakDetector(d.id);
    const r = inspect(URL, { agentMode: true });

    expect(r.status).toBe("ok");
    // Opting in makes them reachable, so now they can and do land in the skip
    // list — proving the exclusion above is the gate, not a missing wire.
    for (const d of DETECTORS) expect(r.checksSkipped).toContain(`lexical:${d.id}`);
  });

  it("total structural failure still returns a well-formed ok result", () => {
    for (const s of STRUCTURAL_SCANS) breakScan(s.id);

    let r: ReturnType<typeof inspect>;
    expect(() => {
      r = inspect(URL);
    }).not.toThrow();

    r = inspect(URL);
    expect(r.status).toBe("ok");
    for (const s of STRUCTURAL_SCANS) expect(r.checksSkipped).toContain(`lexical:${s.id}`);
  });

  it("total failure of both layers still returns a well-formed ok result", () => {
    for (const d of DETECTORS) breakDetector(d.id);
    for (const s of STRUCTURAL_SCANS) breakScan(s.id);

    const r = inspect(URL);
    expect(r.status).toBe("ok");
    // Nothing survived to score, so the floor is 0 — but it is a REPORTED floor
    // with every reachable check named, not a silent clean bill of health. This
    // is the single most important assertion in the file: a 0.00 that means
    // "everything broke" must remain distinguishable from a 0.00 that means
    // "this URL is fine", and `checksSkipped` is the only thing carrying it.
    expect(r.score).toBe(0);
    expect(r.reasons).toEqual([]);
    expect(r.checksSkipped.filter((s) => s.startsWith("lexical:"))).toHaveLength(
      ungated.length + STRUCTURAL_SCANS.length,
    );
  });
});

describe("the invalid path's documented skip limitation", () => {
  // inspect.ts states this deliberately: on the invalid path the bare "lexical"
  // token already says the whole lexical layer was not fully applied, so
  // per-scan `lexical:<id>` entries are NOT threaded there — threading them
  // would change the cucumber-pinned invalid CSV value (LINK-hastsuzd).
  //
  // That is a real limitation, not an oversight, and it is invisible without a
  // test: a well-meaning refactor could "fix" it and break the CSV contract.
  it("a failed scan on unparseable input yields the bare lexical token", () => {
    breakScan("ambiguous_authority");
    const r = inspect("https:///evil.com");

    expect(r.status).toBe("invalid");
    // No finding survived, so the whole lexical layer reads as skipped, and the
    // specific scan that failed is NOT named.
    expect(r.checksSkipped).toEqual(["lexical", "resolution", "reputation"]);
    expect(r.checksSkipped).not.toContain("lexical:ambiguous_authority");
  });

  it("an unparseable input whose scan SUCCEEDS still reports the finding", () => {
    // Control: without injection the same input is explained rather than blank,
    // which is what makes the assertion above about the skip channel and not
    // about invalid inputs being empty.
    const r = inspect("https:///evil.com");

    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
    expect(r.checksSkipped).toEqual(["resolution", "reputation"]);
  });
});
