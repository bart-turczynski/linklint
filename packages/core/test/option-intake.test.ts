import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { inspectAsync } from "../src/inspect-async.js";
import { RECOGNIZED_OPTION_KEYS } from "../src/schema/options.js";

/**
 * LINK-sjsxfqoo — the caller-option intake boundary.
 *
 * `inspect()` read the option keys it recognized and dropped the rest without a
 * word, so
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
 * THE CONTRACT. Dropped configuration is REPORTED, in `checksSkipped`:
 *
 *   - `options:<key>` — that named key was supplied and was not applied.
 *   - bare `options`  — the argument itself was not a usable object, so no
 *                       individual key can be named.
 *
 * Both reuse the channel and the `<namespace>:<id>` token grammar the policy and
 * detector loops already use, and the bare/qualified pair mirrors bare `policy`
 * (the dispatcher failed) versus `policy:<axis id>` (one axis failed).
 *
 * Reporting rather than throwing is forced, not chosen: `inspect()`'s
 * never-throws guarantee is unconditional (A1 / LINK-zsbeqtcr), so rejecting an
 * unknown key has to be an OUTCOME. The never-throws family below spans the
 * before and after of the fix and must never invert.
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
// The acceptance bar: told apart FROM THE RESULT ALONE
// ---------------------------------------------------------------------------

describe("an unrecognized option key is reported, not silently dropped", () => {
  it("names the dropped key in checksSkipped", () => {
    const typo = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["example.com"] }));

    expect(typo.checksSkipped).toContain("options:allowHost");
  });

  it("is no longer byte-identical to passing no options at all", () => {
    // THE ACCEPTANCE BAR. Before the fix these two were deep-equal, so a caller
    // holding only the first could not tell that a policy had been requested
    // and ignored. The difference must be readable off ONE result — no control
    // run to diff against — which the token above provides.
    const typo = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["example.com"] }));
    const nothing = inspect(URL_UNDER_TEST);

    expect(typo).not.toEqual(nothing);
    expect(nothing.checksSkipped).not.toContain("options:allowHost");
    expect(nothing.checksSkipped.some((token) => token.startsWith("options"))).toBe(false);
  });

  it("holds for a mistyped key on every axis, and outside policy too", () => {
    const cases = [
      "allowTld",
      "denyScheme",
      "denyPort",
      "suppressReason",
      // Not a policy key at all: intake covers the whole option surface, which
      // is why the token namespace is `options:` and not `policy:`.
      "maxDecodeDeph",
      "agentmode",
    ];
    for (const key of cases) {
      const result = inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }));
      expect(result.checksSkipped, key).toContain(`options:${key}`);
    }
  });

  it("reports the typo even when a correctly-spelled sibling is also present", () => {
    // The dangerous shape: policy visibly ran, so `checksRun` looks reassuring,
    // while one of the two axes the caller asked for was never configured.
    const result = inspect(
      URL_UNDER_TEST,
      asCallerOptions({ allowHost: ["a.com"], allowHosts: ["b.com"] }),
    );

    expect(result.checksRun).toEqual(["lexical", "policy"]);
    expect(result.checksSkipped).toContain("options:allowHost");
  });

  it("reports every dropped key, not just the first", () => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ zzz: 1, aaa: 2, mmm: 3 }));

    expect(result.checksSkipped).toContain("options:aaa");
    expect(result.checksSkipped).toContain("options:mmm");
    expect(result.checksSkipped).toContain("options:zzz");
  });

  it("leads checksSkipped with the intake tokens — intake precedes every check", () => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: ["a.com"] }));

    expect(result.checksSkipped).toEqual([
      "options:allowHost",
      "resolution",
      "reputation",
    ]);
  });

  it("reports the dropped key on the invalid path too", () => {
    // An input that fails to parse must still report the configuration the
    // caller lost; otherwise the one result a fail-closed consumer inspects
    // most carefully is the one that hides the mistake.
    const result = inspect("ht!tp://%%%not a url", asCallerOptions({ allowHost: ["a.com"] }));

    expect(result.status).toBe("invalid");
    expect(result.checksSkipped).toEqual([
      "options:allowHost",
      "lexical",
      "resolution",
      "reputation",
    ]);
  });

  it("reports the dropped key even when the input is not a string", () => {
    const result = inspect(42 as unknown as string, asCallerOptions({ allowHost: ["a.com"] }));

    expect(result.status).toBe("invalid");
    expect(result.checksSkipped).toContain("options:allowHost");
  });
});

describe("a recognized option key is never reported as dropped", () => {
  it("stays byte-for-byte unchanged for a well-formed call", () => {
    // The default path must not move. Absent an unrecognized key there is no
    // `options` token of either form, so every existing consumer sees exactly
    // the pre-existing output.
    const configured = inspect(URL_UNDER_TEST, { allowHosts: ["example.com"] });

    expect(configured.checksRun).toEqual(["lexical", "policy"]);
    expect(configured.checksSkipped).toEqual(["resolution", "reputation"]);
  });

  it("says nothing about an unrecognized key explicitly set to undefined", () => {
    // `{ ...base, allowHost: undefined }` configured nothing, so nothing was
    // lost — matching how `policyConfigured` already treats `undefined`.
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ allowHost: undefined }));

    expect(result).toEqual(inspect(URL_UNDER_TEST));
  });

  it("recognizes every key the option interfaces declare", () => {
    // The runtime key set is a literal; the interfaces are the truth. The sync
    // half is additionally locked at compile time by
    // `Record<keyof InspectOptions, true>`, but the four async-only keys cannot
    // be (a runtime import from inspect-async.ts would close a cycle), so both
    // are asserted here off the source — the same technique docs-examples.test
    // uses for the documented option surface.
    const declared = [
      ...declaredKeys(SOURCE_OPTIONS, "export interface InspectOptions {"),
      ...declaredKeys(SOURCE_ASYNC, "export interface InspectAsyncOptions extends InspectOptions {"),
    ];

    expect(declared.length).toBeGreaterThanOrEqual(17);
    expect(declared).toContain("allowHosts");
    expect(declared).toContain("enrichers");
    for (const key of declared) {
      expect([...RECOGNIZED_OPTION_KEYS], key).toContain(key);
    }
  });

  it("recognizes nothing the interfaces do not declare", () => {
    const declared = new Set([
      ...declaredKeys(SOURCE_OPTIONS, "export interface InspectOptions {"),
      ...declaredKeys(SOURCE_ASYNC, "export interface InspectAsyncOptions extends InspectOptions {"),
    ]);
    for (const key of RECOGNIZED_OPTION_KEYS) {
      expect([...declared], key).toContain(key);
    }
  });
});

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const SOURCE_OPTIONS = readFileSync(join(SRC, "schema", "options.ts"), "utf8");
const SOURCE_ASYNC = readFileSync(join(SRC, "inspect-async.ts"), "utf8");

/** Optional property names declared directly in one interface body. */
function declaredKeys(source: string, header: string): string[] {
  const start = source.indexOf(header);
  expect(start, header).toBeGreaterThan(-1);
  const body = source.slice(start, source.indexOf("\n}", start));
  return [...body.matchAll(/^ {2}([a-zA-Z][a-zA-Z0-9]*)\?:/gm)].map((m) => m[1] as string);
}

// ---------------------------------------------------------------------------
// An options ARGUMENT that is not a usable object
// ---------------------------------------------------------------------------

describe("an unusable options argument is reported, not a crash", () => {
  const UNUSABLE: ReadonlyArray<readonly [string, unknown]> = [
    ["null", null],
    ["a string", "allowHosts"],
    ["a number", 42],
    ["a boolean", true],
    ["a function", () => ["example.com"]],
    ["a Proxy trapping ownKeys", new Proxy({}, { ownKeys() { throw new Error("boom"); } })],
  ];

  it.each(UNUSABLE)("does not throw: %s", (_label, value) => {
    // `options: InspectOptions = {}` defaults on `undefined` only, so an
    // explicit null — what `JSON.parse('{"options":null}')` hands a plain-JS
    // caller — used to reach `normalizeOptions` and dereference.
    expect(() => inspect(URL_UNDER_TEST, asCallerOptions(value))).not.toThrow();
  });

  it.each(UNUSABLE)("reports the bare `options` token: %s", (_label, value) => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions(value));

    expect(result.status).toBe("ok");
    expect(result.checksSkipped).toEqual(["options", "resolution", "reputation"]);
  });

  it.each(UNUSABLE)("inspectAsync resolves rather than rejecting: %s", async (_label, value) => {
    const result = await inspectAsync(URL_UNDER_TEST, asCallerOptions(value));
    expect(result.checksSkipped).toContain("options");
  });

  it("never emits the bare and the qualified form together", () => {
    // The same invariant docs/architecture.md §5 states for the policy channel:
    // bare `policy` (the dispatcher failed, nothing can be named) and
    // `policy:<axis id>` never describe the same run.
    for (const value of [null, "x", 7, { allowHost: 1 }, { allowHosts: ["a.com"] }, {}]) {
      const tokens = inspect(URL_UNDER_TEST, asCallerOptions(value)).checksSkipped;
      const bare = tokens.includes("options");
      const qualified = tokens.some((token) => token.startsWith("options:"));
      expect(bare && qualified, JSON.stringify(value)).toBe(false);
    }
  });

  it("an empty options object is still a well-formed call", () => {
    expect(inspect(URL_UNDER_TEST, {})).toEqual(inspect(URL_UNDER_TEST));
  });
});

// ---------------------------------------------------------------------------
// inspectAsync inherits the intake — it does not re-implement it
// ---------------------------------------------------------------------------

describe("inspectAsync inherits the option intake", () => {
  it("carries the dropped-key token through to the enriched result", async () => {
    const result = await inspectAsync(
      URL_UNDER_TEST,
      asCallerOptions({ allowHost: ["example.com"] }),
    );

    expect(result.checksSkipped).toContain("options:allowHost");
  });

  it("does not report its own async-only keys as dropped", async () => {
    // inspectAsync hands its whole superset object to inspect(), so the
    // synchronous intake has to recognize `enrichers`/`signal`/`cache`/
    // `governor` or every enriched call would accuse itself.
    const controller = new AbortController();
    const result = await inspectAsync(URL_UNDER_TEST, {
      enrichers: [],
      signal: controller.signal,
    });

    expect(result.checksSkipped.some((token) => token.startsWith("options"))).toBe(false);
  });

  it("still returns byte-identical output to inspect() with no enrichers", async () => {
    const sync = inspect(URL_UNDER_TEST, { allowHosts: ["example.com"] });
    const async = await inspectAsync(URL_UNDER_TEST, { allowHosts: ["example.com"] });

    expect(async).toEqual(sync);
  });
});

// ---------------------------------------------------------------------------
// Token hygiene: bounded, delimiter-safe, deterministic
// ---------------------------------------------------------------------------

describe("intake tokens are bounded, delimiter-safe and deterministic", () => {
  it("folds characters that would forge a token or list delimiter", () => {
    // `checksSkipped` is a list of `<namespace>:<id>` tokens that consumers
    // split, join and render — the cucumber suite joins it on commas. A key
    // carrying a comma, colon, newline or control character must not be able to
    // forge one. The substitution is lossy on purpose: the token names the
    // mistake, it is not a round-trip of it.
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ "a,b\nc:d\u0000e": 1 }));
    const token = result.checksSkipped.find((t) => t.startsWith("options:"));

    expect(token).toBe("options:a_b_c_d_e");
    expect(token).not.toContain(",");
    expect(token).not.toContain("\n");
  });

  it("bounds an absurdly long key", () => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ ["x".repeat(4096)]: 1 }));
    const token = result.checksSkipped.find((t) => t.startsWith("options:"));

    expect(token).toBeDefined();
    expect(token!.length).toBeLessThanOrEqual("options:".length + 65);
  });

  it("does not repeat a token when two keys collapse to the same one", () => {
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ "a b": 1, "a,b": 2 }));
    const tokens = result.checksSkipped.filter((t) => t.startsWith("options:"));

    expect(tokens).toEqual(["options:a_b"]);
  });

  it("does not depend on the caller's key insertion order", () => {
    // The published determinism guarantee is "same input + same package
    // version → same verdict" (A3, narrowed under LINK-ephrdynz). Two objects
    // that differ only in insertion order are the same input.
    const forward = inspect(URL_UNDER_TEST, asCallerOptions({ bbb: 1, aaa: 2 }));
    const reverse = inspect(URL_UNDER_TEST, asCallerOptions({ aaa: 2, bbb: 1 }));

    expect(forward).toEqual(reverse);
    expect(forward.checksSkipped).toEqual(["options:aaa", "options:bbb", "resolution", "reputation"]);
  });

  it("reads only own enumerable keys, never the prototype chain", () => {
    // A class instance or an `Object.create` result must not have its inherited
    // members reported as dropped configuration.
    class Config {
      allowHosts = ["example.com"];
      helper(): string {
        return "not an option";
      }
    }
    const result = inspect(URL_UNDER_TEST, asCallerOptions(new Config()));

    expect(result.checksRun).toEqual(["lexical", "policy"]);
    expect(result.checksSkipped).toEqual(["resolution", "reputation"]);
  });
});

// ---------------------------------------------------------------------------
// NEVER-THROWS (A1 / LINK-zsbeqtcr) — held before the fix, holds after
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
  ["tab in key", "a\tb"],
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

  it.each(HOSTILE_KEYS)("reports it rather than swallowing it: %s", (_label, key) => {
    // Not throwing is only half the contract — a hostile key must still be
    // NAMED, or the fix would have replaced a crash with the silence it exists
    // to remove. A COMPUTED `__proto__` (which is how a parsed JSON body and
    // every case here arrives) defines an ordinary own property, so it is
    // enumerated and reported like any other key.
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ [key]: ["x"] }));

    expect(
      result.checksSkipped.some((token) => token.startsWith("options:")),
      key,
    ).toBe(true);
  });

  it("says nothing when literal `__proto__:` syntax sets no own key", () => {
    // The one asymmetry worth naming: in an object LITERAL, `__proto__:` is the
    // prototype setter, not a property definition. It defines no own key, so it
    // configures nothing and there is nothing to report.
    const result = inspect(URL_UNDER_TEST, asCallerOptions({ __proto__: { allowHost: 1 } }));

    expect(result).toEqual(inspect(URL_UNDER_TEST));
  });

  it("does not throw when an unknown key's getter throws", () => {
    const booby = asCallerOptions({
      get allowHost(): string[] {
        throw new Error("boom");
      },
    });
    expect(() => inspect(URL_UNDER_TEST, booby)).not.toThrow();
  });

  it("reports an unknown key whose value cannot even be read", () => {
    // It was supplied and it was not applied. That is the same statement as an
    // unrecognized key, so it gets the same token rather than silence.
    const booby = asCallerOptions({
      get allowHost(): string[] {
        throw new Error("boom");
      },
    });
    expect(inspect(URL_UNDER_TEST, booby).checksSkipped).toContain("options:allowHost");
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
