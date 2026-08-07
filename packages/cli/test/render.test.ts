import { describe, expect, it } from "vitest";
import { inspect, type InspectResult } from "linklint";
import { renderJson, renderResults } from "@linklint/cli";

const benign: InspectResult = inspect("https://www.example.com/path");
const medium: InspectResult = inspect("https://paypal.com@evil.example.com/login");
const invalid: InspectResult = inspect("ht!tp://%%%not a url");

describe("renderJson", () => {
  it("returns valid JSON parseable back to the results array", () => {
    const json = renderJson([benign, medium]);
    const parsed = JSON.parse(json) as InspectResult[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]?.input).toBe("https://www.example.com/path");
    expect(parsed[1]?.input).toBe("https://paypal.com@evil.example.com/login");
    expect(parsed).toEqual([benign, medium]);
  });

  it("renders an empty array for no results", () => {
    expect(JSON.parse(renderJson([]))).toEqual([]);
  });
});

describe("renderResults — full (human) mode", () => {
  it("contains the severity badge, score, and input", () => {
    const out = renderResults([benign], { quiet: false, noColor: true });
    expect(out).toContain("INFO");
    expect(out).toContain("0.00");
    expect(out).toContain("https://www.example.com/path");
  });

  it("renders an INVALID badge and a do-not-assume-safe line for invalid input", () => {
    const out = renderResults([invalid], { quiet: false, noColor: true });
    expect(out).toContain("INVALID");
    expect(out).toContain("do not assume safe");
  });

  // LINK-vwjtdtzn — the clean case needs the same fail-closed caveat as
  // `invalid` above, and needs it more: a green INFO badge beside a bare
  // "reasons: none" is the surface most likely to be read as clearance.
  // architecture.md §1.1 is canonical.
  it("qualifies a clean result rather than presenting it as a safety verdict", () => {
    const out = renderResults([benign], { quiet: false, noColor: true });
    expect(out).toContain("reasons: none");
    expect(out).toContain("not a safety verdict");
    // The words that would make a zero read as an endorsement.
    expect(out).not.toMatch(/\b(safe|clean|OK|passed)\b/);
  });
});

describe("renderResults — quiet mode", () => {
  it("renders a single tab-separated line with badge + score + input", () => {
    const out = renderResults([medium], { quiet: true, noColor: true });
    expect(out).not.toContain("\n");
    expect(out).toContain("MEDIUM");
    expect(out).toContain("0.50");
    expect(out).toContain("https://paypal.com@evil.example.com/login");
    expect(out.split("\t")).toHaveLength(3);
  });
});

/**
 * LINK-elzuacby — `pslSnapshot.stale` is tri-state and ONE-DIRECTIONAL: the
 * bundled date is a packaging-release proxy that bounds the snapshot's age from
 * below, so `true` is proven staleness, `null` is undetermined (the normal value
 * for the pinned bundle) and `false` is reachable only from an exact snapshot
 * date. The CLI must warn on the proven case and stay silent on the other two —
 * `!== false` would put a warning on every ordinary run and drown the real one.
 *
 * The snapshot is substituted rather than clock-driven, so all three states are
 * covered on any calendar date and after any tldts bump.
 */
describe("renderResults — PSL staleness advisory (tri-state)", () => {
  const withSnapshot = (stale: boolean | null): InspectResult => ({
    ...benign,
    pslSnapshot: { date: "2026-06-15", stale },
  });
  const render = (stale: boolean | null): string =>
    renderResults([withSnapshot(stale)], { quiet: false, noColor: true });

  it("warns when the snapshot is provably stale", () => {
    const out = render(true);
    expect(out).toContain("PSL snapshot (2026-06-15) is stale");
  });

  it("stays silent when staleness is undetermined", () => {
    expect(render(null)).not.toContain("PSL snapshot");
  });

  it("stays silent when the snapshot is provably fresh", () => {
    expect(render(false)).not.toContain("PSL snapshot");
  });

  it("names the unknown date rather than printing null", () => {
    const out = renderResults([{ ...benign, pslSnapshot: { date: null, stale: true } }], {
      quiet: false,
      noColor: true,
    });
    expect(out).toContain("PSL snapshot (unknown date) is stale");
  });
});

describe("renderResults — color control", () => {
  it("emits no ANSI escape when noColor is true", () => {
    const out = renderResults([medium], { quiet: false, noColor: true });
    expect(out).not.toContain("[");
  });

  it("emits an ANSI escape when noColor is false", () => {
    const out = renderResults([medium], { quiet: false, noColor: false });
    expect(out).toContain("[");
  });
});
