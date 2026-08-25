import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { inspectAsync } from "../src/inspect-async.js";

/**
 * LINK-sjsxfqoo — the caller-option intake boundary.
 *
 * `inspect()` accepted whatever object it was handed and read only the keys it
 * recognized. Everything else was dropped without a word, so
 *
 *     inspect(url, { allowHost:  ["example.com"] })   // singular typo
 *     inspect(url, { allowHosts: ["example.com"] })   // what was meant
 *
 * differed by a whole policy channel, while the first was byte-identical to a
 * run with no options at all. Nothing in the RESULT separated "you asked for a
 * policy and I ignored it" from "you asked for nothing" — and the failure
 * direction is OPEN, in the one channel whose entire purpose is restriction.
 *
 * REACH. A TypeScript caller passing an object LITERAL is already protected:
 * excess-property checking rejects `allowHost` at compile time. The exposure is
 * everywhere options do NOT arrive as a literal — JSON config, MCP tool input,
 * plain-JS callers, options widened through a variable, anything crossing a
 * boundary as `any`. This is a RUNTIME contract gap, not a type-system gap, and
 * every case below is written the way such a caller reaches the function.
 *
 * This file is written in two layers, deliberately:
 *
 *  - PIN (commit 1) — the behaviour as it shipped, so the change is a visible
 *    diff rather than a claim. The silent-loss pins below are INVERTED by the
 *    fix; they are kept, rewritten, as the contract assertions.
 *  - CONTRACT (commit 2) — what a caller may now rely on.
 *
 * The never-throws pins (A1 / LINK-zsbeqtcr) span both and must never invert:
 * whatever the intake decides about an unknown key, deciding it is a REPORTED
 * OUTCOME, never an exception.
 */

const URL_UNDER_TEST = "https://evil.com/";

/**
 * How a non-literal caller actually reaches `inspect()`. Widening to a bare
 * object type is what removes excess-property checking — the same erasure a
 * `JSON.parse` result or an MCP tool argument arrives with.
 */
function asCallerOptions(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// PIN — silent option loss (inverted by the fix)
// ---------------------------------------------------------------------------

describe("PIN: an unrecognized option key is dropped without a trace", () => {
  it("the singular typo yields no policy channel at all", () => {
    const typo = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["example.com"] }));
    const meant = inspect(URL_UNDER_TEST, { allowHosts: ["example.com"] });

    expect(typo.checksRun).toEqual(["lexical"]);
    expect(meant.checksRun).toEqual(["lexical", "policy"]);
  });

  it("the typo'd result is byte-identical to passing no options at all", () => {
    // THE DEFECT, stated as an equality. A caller holding only this result
    // cannot tell it apart from one where no policy was ever requested — the
    // acceptance bar the fix has to clear is exactly this line going red.
    const typo = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["example.com"] }));
    const nothing = inspect(URL_UNDER_TEST);

    expect(typo).toEqual(nothing);
  });

  it("holds for a mistyped key on every axis, not just host", () => {
    for (const key of ["allowTld", "denyScheme", "denyPort", "suppressReason"]) {
      const result = inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }));
      expect(result, key).toEqual(inspect(URL_UNDER_TEST));
    }
  });
});

// ---------------------------------------------------------------------------
// PIN — the options argument itself is unguarded (fixed in commit 2)
// ---------------------------------------------------------------------------

describe("PIN: a non-object options argument crashes the intake", () => {
  it("null options throw a TypeError out of inspect()", () => {
    // `options: InspectOptions = {}` defaults on `undefined` only, so an
    // explicit null — exactly what `JSON.parse('{"options":null}')` hands a
    // plain-JS caller — reaches `normalizeOptions` and dereferences.
    expect(() => inspect(URL_UNDER_TEST, asCallerOptions(null))).toThrow(TypeError);
  });

  it("null options reject out of inspectAsync() too", async () => {
    await expect(inspectAsync(URL_UNDER_TEST, asCallerOptions(null))).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// NEVER-THROWS (A1 / LINK-zsbeqtcr) — must hold before AND after the fix
// ---------------------------------------------------------------------------

/**
 * Keys chosen to be hostile in the ways an option key can be hostile: a plain
 * typo, prototype-adjacent names, a name that collides with the `<channel>:<id>`
 * token grammar `checksSkipped` uses, whitespace/control characters that would
 * corrupt a joined rendering, and a key long enough to bloat a serialized
 * result. None of them may become an exception.
 */
const HOSTILE_KEYS: ReadonlyArray<readonly [string, string]> = [
  ["plain typo", "allowHost"],
  ["prototype pollution attempt", "__proto__"],
  ["constructor", "constructor"],
  ["prototype", "prototype"],
  ["toString", "toString"],
  ["token-grammar collision", "policy:host"],
  ["channel-token collision", "resolution"],
  ["comma (delimiter) in key", "a,b"],
  ["newline in key", "a\nb"],
  ["NUL character in key", "a\u0000b"],
  ["astral character in key", "🙈"],
  ["empty key", ""],
  ["very long key", "x".repeat(4096)],
];

describe("never-throws: a hostile or typo'd option key is a reported outcome", () => {
  it.each(HOSTILE_KEYS)("does not throw: %s", (_label, key) => {
    expect(() => inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }))).not.toThrow();
  });

  it.each(HOSTILE_KEYS)("still returns a schema-valid ok result: %s", (_label, key) => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }));

    expect(result.status).toBe("ok");
    expect(typeof result.score).toBe("number");
    expect(Array.isArray(result.checksRun)).toBe(true);
    expect(Array.isArray(result.checksSkipped)).toBe(true);
  });

  it.each(HOSTILE_KEYS)("stays JSON-serializable: %s", (_label, key) => {
    // The CLI --json path and the MCP channel both serialize the result, so an
    // unrepresentable token would fail at the boundary rather than here.
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }));
    expect(() => JSON.stringify(result)).not.toThrow();
  });

  it("does not throw when an unknown key's getter throws", () => {
    const booby = asCallerOptions({
      get allowHost(): string[] {
        throw new Error("boom");
      },
    });
    expect(() => inspect(URL_UNDER_TEST, booby)).not.toThrow();
  });

  it("does not throw when key enumeration itself throws", () => {
    const trapped = asCallerOptions(
      new Proxy(
        {},
        {
          ownKeys() {
            throw new Error("ownKeys boom");
          },
        },
      ),
    );
    expect(() => inspect(URL_UNDER_TEST, trapped)).not.toThrow();
  });

  it("does not throw on an unknown key carried alongside a real one", () => {
    expect(() =>
      inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["a.com"], allowHosts: ["b.com"] })),
    ).not.toThrow();
  });
});
