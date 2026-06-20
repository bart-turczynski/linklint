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
