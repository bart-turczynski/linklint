import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { normalizeOptions, normalizeSuppressReasons } from "../src/parse/runtime.js";
import { RECOGNIZED_OPTION_KEYS } from "../src/schema/options.js";

/**
 * LINK-wutunnbk — the caller-option trim is a property of every LIST-VALUED
 * option, not of the policy axes.
 *
 * MR !41 (LINK-uxkrtcnw) put the trim inside `normalizedList` precisely so that
 * every list would inherit it by construction. `docs/architecture.md` §8 then
 * described it as a property of "the string axes", and that framing is what let
 * two more list-valued options stay silently void for months: `idnAllowlist`
 * was normalized inline and `suppressReasons` trimmed neither of its two caller
 * strings, because every reader — the original fix, its issue text and its
 * review — checked "the eight policy axes" and stopped there (LINK-qajalduf).
 *
 * Prose alone cannot stop that recurring, so the classification is DERIVED here
 * rather than restated:
 *
 *   1. the option keys come from the two option interfaces, parsed from source
 *      (the technique `option-intake.test.ts` already uses, because
 *      `SYNC_OPTION_KEYS` is `Record<keyof InspectOptions, true>` — the
 *      compiler enforces key COMPLETENESS but keeps no type information at
 *      runtime, so which keys are list-valued is not readable off it);
 *   2. list-valued means the declared type is an array, resolving a one-level
 *      type alias so `enrichers?: EnrichmentPlan` is not missed;
 *   3. routed means the key literally appears as `normalizedList(options.<key>`
 *      in `parse/runtime.ts`;
 *   4. anything list-valued and NOT routed must be named in one of the two
 *      exception maps below, with its reason.
 *
 * So a new list-valued option that is normalized inline fails here by default,
 * which is the failure mode this ticket exists to close.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "src");

const SOURCE_OPTIONS = readFileSync(join(SRC, "schema", "options.ts"), "utf8");
const SOURCE_ASYNC = readFileSync(join(SRC, "inspect-async.ts"), "utf8");
const SOURCE_RUNTIME = readFileSync(join(SRC, "parse", "runtime.ts"), "utf8");

/**
 * The list-valued options that deliberately do NOT route through
 * `normalizedList`, each with the reason it cannot. Being in this map is a
 * decision a human made; being absent from it is the default, and the default
 * is "must route".
 */
const FIELD_TRIMMED: Readonly<Record<string, string>> = {
  suppressReasons:
    "entries are objects, so there is no single value for a list-level " +
    "normalizer to trim; the `code` and `host` fields get the identical trim " +
    "through the shared `trimListValue` helper",
};

/** List-valued options that carry no caller configuration text at all. */
const OUT_OF_CLASS: Readonly<Record<string, string>> = {
  enrichers:
    "provider objects supplied in code rather than configuration text a " +
    "caller typed or split, so a padded value there is visibly wrong rather " +
    "than silently void",
};

/** `name?: type;` pairs declared directly in one interface body. */
function declaredOptions(source: string, header: string): [string, string][] {
  const start = source.indexOf(header);
  expect(start, header).toBeGreaterThan(-1);
  const body = source.slice(start, source.indexOf("\n}", start));
  return [...body.matchAll(/^ {2}([a-zA-Z][a-zA-Z0-9]*)\?:\s*([^;]+);/gm)].map((m) => [
    m[1] as string,
    (m[2] as string).trim(),
  ]);
}

/** Every single-line `export type X = …;` alias in the core package. */
function typeAliases(dir: string, into: Map<string, string> = new Map()): Map<string, string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) typeAliases(path, into);
    else if (entry.name.endsWith(".ts")) {
      for (const m of readFileSync(path, "utf8").matchAll(
        /^export type ([A-Za-z0-9_]+)\s*=\s*([^;]+);/gm,
      )) {
        into.set(m[1] as string, (m[2] as string).trim());
      }
    }
  }
  return into;
}

const ALIASES = typeAliases(SRC);

function isListValued(type: string, depth = 0): boolean {
  const bare = type.replace(/^readonly\s+/, "").trim();
  if (bare.endsWith("[]")) return true;
  const alias = ALIASES.get(bare);
  return alias !== undefined && depth < 3 ? isListValued(alias, depth + 1) : false;
}

const DECLARED = [
  ...declaredOptions(SOURCE_OPTIONS, "export interface InspectOptions {"),
  ...declaredOptions(SOURCE_ASYNC, "export interface InspectAsyncOptions extends InspectOptions {"),
];
const LIST_VALUED = DECLARED.filter(([, type]) => isListValued(type)).map(([key]) => key);
const ROUTED = [...SOURCE_RUNTIME.matchAll(/normalizedList\(\s*options\.([A-Za-z0-9_]+)/g)].map(
  (m) => m[1] as string,
);

describe("the trim covers every list-valued caller option (LINK-wutunnbk)", () => {
  it("derives the option surface from the interfaces, not from a literal here", () => {
    expect(DECLARED.map(([key]) => key).sort()).toEqual([...RECOGNIZED_OPTION_KEYS].sort());
    expect(LIST_VALUED).toContain("idnAllowlist");
    expect(LIST_VALUED).toContain("suppressReasons");
    // `enrichers?: EnrichmentPlan` is an alias for `readonly Enricher[]`. A
    // derivation that stopped at the syntactic `[]` would silently under-count
    // the class it is meant to enumerate.
    expect(LIST_VALUED).toContain("enrichers");
  });

  it.each(LIST_VALUED)("%s is trimmed, or says why it cannot be", (key) => {
    const covered =
      ROUTED.includes(key) || key in FIELD_TRIMMED || key in OUT_OF_CLASS;
    expect(
      covered,
      `${key} is list-valued and does not route through normalizedList(). ` +
        "Route it there rather than normalizing it inline — that is exactly " +
        "how idnAllowlist lost the trim for a release (LINK-qajalduf). If it " +
        "genuinely cannot route, name it in FIELD_TRIMMED or OUT_OF_CLASS " +
        "with the reason, and update docs/architecture.md §8.",
    ).toBe(true);
  });

  it("keeps no stale exception: every exception is still list-valued and unrouted", () => {
    for (const key of [...Object.keys(FIELD_TRIMMED), ...Object.keys(OUT_OF_CLASS)]) {
      expect(LIST_VALUED, key).toContain(key);
      expect(ROUTED, key).not.toContain(key);
    }
  });

  it("routes the seven policy axes and idnAllowlist through the one choke point", () => {
    expect([...ROUTED].sort()).toEqual([
      "allowHosts",
      "allowSchemes",
      "allowTlds",
      "denyHosts",
      "denyPorts",
      "denySchemes",
      "denyTlds",
      "idnAllowlist",
    ]);
  });
});

describe("the trim itself, on both sides of the exception", () => {
  it("trims a routed non-policy list (idnAllowlist)", () => {
    const config = normalizeOptions({ idnAllowlist: ["  München.DE  "] });

    expect([...config.idnAllowlist]).toEqual(["münchen.de"]);
  });

  it("trims both caller strings of a suppressReasons rule, field-wise", () => {
    // A padded `code` is not representable in a TypeScript object literal
    // (`code` is a `ReasonCode`), so the rule is written the way the callers
    // who actually hit this reach it — JSON config, MCP tool input, anything
    // crossing a boundary as `any` — which is the same reach argument
    // `option-intake.test.ts` makes. `host` is a plain `string`, so its half
    // was reachable from typed code too.
    const rules = [{ code: "  idn_host  ", host: "  Example.COM  " }] as unknown as Parameters<
      typeof normalizeSuppressReasons
    >[0];

    expect(normalizeSuppressReasons(rules)).toEqual([{ code: "idn_host", host: "example.com" }]);
  });

  it("leaves a numeric axis alone — the trim is scalar-safe, not string-only", () => {
    expect(normalizeOptions({ denyPorts: [8080] }).policy.denyPorts.values).toEqual([8080]);
  });
});
