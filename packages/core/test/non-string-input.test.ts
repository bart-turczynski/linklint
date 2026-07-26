import { describe, expect, it } from "vitest";
import { inspect, inspectAsync } from "../src/index.js";
import { SCHEMA_VERSION } from "../src/schema/base.js";

/**
 * LINK-zsbeqtcr — the never-throws guarantee is UNCONDITIONAL, not string-only.
 *
 * `inspect(input: string)` is typed, and the MCP channel validates with
 * `z.string()` while the CLI only ever passes argv/stdin — so the exposed caller
 * is a plain-JS library consumer with no compile-time checking. That is a real
 * audience for a published npm package, and `JSON.parse` handing back `null` is
 * the obvious path to it.
 *
 * Before this suite, such a caller got a `TypeError` out of `prepare()`'s
 * `input.trim()`. That matters beyond tidiness: an uncaught throw inside a
 * link-checking hook fails **open**, which is the exact failure mode linklint
 * exists to prevent. The guard fails **closed** instead — `status: "invalid"`,
 * which docs/reason-codes.md already pins as *not benign*.
 *
 * This suite pins both halves: it never throws, AND the result it returns is a
 * schema-valid invalid result (not some half-built object).
 */

/** Inputs a plain-JS or JSON-fed caller can realistically produce. */
const NON_STRINGS: ReadonlyArray<readonly [string, unknown]> = [
  ["null", null],
  ["undefined", undefined],
  ["number", 12345],
  ["NaN", Number.NaN],
  ["Infinity", Number.POSITIVE_INFINITY],
  ["boolean true", true],
  ["boolean false", false],
  ["plain object", { url: "https://example.com" }],
  ["array", ["https://example.com"]],
  ["null-prototype object", Object.create(null)],
  ["Date", new Date(0)],
  ["RegExp", /https:\/\/example\.com/],
  ["Map", new Map()],
  ["bigint", 10n],
  ["symbol", Symbol("https://example.com")],
  ["function", () => "https://example.com"],
  ["String object (not a primitive)", new String("https://example.com")],
];

/** Hostile shapes whose own coercion is booby-trapped. */
const HOSTILE_COERCION: ReadonlyArray<readonly [string, unknown]> = [
  ["object with throwing toString", { toString() { throw new Error("boom"); } }],
  ["object with throwing valueOf", { valueOf() { throw new Error("boom"); }, toString: undefined }],
  ["Proxy trapping get", new Proxy({}, { get() { throw new Error("proxy boom"); } })],
  ["Proxy trapping has", new Proxy({}, { has() { throw new Error("has boom"); } })],
  ["object with recursive toString", { toString(): string { return (this as { toString(): string }).toString(); } }],
];

const ALL = [...NON_STRINGS, ...HOSTILE_COERCION];

describe("inspect() never throws on non-string input (LINK-zsbeqtcr)", () => {
  it.each(ALL)("returns instead of throwing: %s", (_label, value) => {
    expect(() => inspect(value as string)).not.toThrow();
  });

  it.each(ALL)("returns a schema-valid invalid result: %s", (_label, value) => {
    const r = inspect(value as string);

    expect(r.status).toBe("invalid");
    // The invalid contract (A3 / LINK-ctkfbdkf): a fail-closed consumer keys off
    // these three, so a non-string must not look "checked and clean".
    expect(r.score).toBeNull();
    expect(r.severity).toBeNull();
    expect(r.parsed).toBeNull();

    expect(r.schemaVersion).toBe(SCHEMA_VERSION);
    // `input` is pinned to string by the result schema — coercion must not leak
    // a non-string through, even when the value's own toString is booby-trapped.
    expect(typeof r.input).toBe("string");
    expect(Array.isArray(r.reasons)).toBe(true);
    expect(Array.isArray(r.confusables)).toBe(true);
  });

  it.each(ALL)("stays JSON-serializable: %s", (_label, value) => {
    // The CLI's --json path and the MCP channel both serialize the result. A
    // result that cannot round-trip would break those surfaces at the edge.
    const r = inspect(value as string);
    expect(() => JSON.stringify(r)).not.toThrow();
    const round = JSON.parse(JSON.stringify(r));
    expect(round.status).toBe("invalid");
    expect(round.score).toBeNull();
  });

  it("explains itself rather than emitting a bare parse_error", () => {
    // Explainability is the product claim; "not a parseable URL or hostname" is
    // actively misleading for a caller who passed null. The sharpened detail
    // rides on the existing parse_error code, so the reason-code registry and
    // its documented count are untouched.
    const r = inspect(null as unknown as string);
    expect(r.reasons).toHaveLength(1);
    expect(r.reasons[0]!.code).toBe("parse_error");
    expect(r.reasons[0]!.weight).toBe(0);
    expect(r.reasons[0]!.detail).toContain("not a string");
    expect(r.reasons[0]!.detail).toContain("null");
  });

  it("names the offending type, distinguishing null from undefined", () => {
    // `typeof null === "object"` would misreport the most common case of all.
    expect(inspect(null as unknown as string).reasons[0]!.detail).toContain("null");
    expect(inspect(undefined as unknown as string).reasons[0]!.detail).toContain("undefined");
    expect(inspect(42 as unknown as string).reasons[0]!.detail).toContain("number");
  });

  it("echoes an empty input when the value cannot be coerced at all", () => {
    // String() is itself partial. Falling back to "" keeps the schema's
    // `input: string` honest rather than throwing on the way out.
    const r = inspect({ toString() { throw new Error("boom"); } } as unknown as string);
    expect(r.input).toBe("");
    expect(r.status).toBe("invalid");
  });

  it("coerces a benign non-string into a readable echo", () => {
    expect(inspect(12345 as unknown as string).input).toBe("12345");
    expect(inspect(null as unknown as string).input).toBe("null");
  });

  it("does not treat a String object as a usable URL", () => {
    // `new String(x)` is typeof "object". Coercing it to its wrapped value would
    // be a silent contract widening; it fails closed like every other non-string.
    const r = inspect(new String("https://example.com") as unknown as string);
    expect(r.status).toBe("invalid");
  });

  it("leaves ordinary string behavior byte-identical", () => {
    // The guard must be a pure addition — the string paths, valid and invalid
    // alike, are untouched.
    const clean = inspect("https://github.com");
    expect(clean.status).toBe("ok");
    expect(clean.score).toBe(0);

    const invalidString = inspect("not a url at all");
    expect(invalidString.status).toBe("invalid");
    expect(invalidString.reasons[0]!.code).toBe("parse_error");
    // The unsharpened default detail still applies to genuine parse failures.
    expect(invalidString.reasons[0]!.detail).toBe("input is not a parseable URL or hostname");
  });
});

describe("inspectAsync() inherits the guard (LINK-zsbeqtcr)", () => {
  it.each(ALL)("rejects nothing and resolves to invalid: %s", async (_label, value) => {
    // inspectAsync delegates stage 1 to inspect(), so the guard must reach it
    // without the async path needing its own copy.
    await expect(inspectAsync(value as string)).resolves.toMatchObject({
      status: "invalid",
      score: null,
    });
  });
});
