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
 * So a new list-valued option that is normalized inline fails here by default
 * — the failure mode this ticket exists to close — and the counts published in
 * `docs/architecture.md` §8 are checked against the same derivation, over
 * whitespace-flattened prose so a hard wrap cannot make the match vacuous.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "src");
const REPO_ROOT = join(HERE, "..", "..", "..");

const SOURCE_OPTIONS = readFileSync(join(SRC, "schema", "options.ts"), "utf8");
const SOURCE_ASYNC = readFileSync(join(SRC, "inspect-async.ts"), "utf8");
const SOURCE_RUNTIME = readFileSync(join(SRC, "parse", "runtime.ts"), "utf8");
const architectureDoc = readFileSync(join(REPO_ROOT, "docs", "architecture.md"), "utf8");

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

/**
 * The behavior itself is pinned in depth by `list-option-trim.test.ts`
 * (LINK-qajalduf). These three cases are held here as well, for the reason
 * `list-option-trim.test.ts` already gives for overlapping
 * `policy-runtime.test.ts`: the claim under test is about the CLASS, not about
 * any one option. They are the evidence behind the classification above —
 * routed, field-trimmed, and scalar-safe — so a reader of the exception maps
 * can see each branch actually holds without leaving the file.
 */
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

/**
 * Whitespace-flattened, blockquote-stripped prose. A doc assertion that matches
 * a raw substring matches NOTHING the moment the sentence it targets hard-wraps
 * — it then passes vacuously and proves nothing. Every sentence asserted below
 * spans a line break in the document as written.
 */
function flatten(markdown: string): string {
  return markdown
    .split("\n")
    .map((line) => line.replace(/^\s*>\s?/, "").trim())
    .join(" ")
    .replace(/\s+/g, " ");
}

describe("docs/architecture.md §8 states the rule, coupled to the derivation", () => {
  const flat = flatten(architectureDoc);

  /** `toContain` on a 2,000-line document prints the whole document on failure. */
  function statesThat(sentence: string): void {
    expect(flat.includes(sentence), `docs/architecture.md §8 must state: ${sentence}`).toBe(true);
  }

  it("scopes the property to list-valued options rather than to the axes", () => {
    statesThat(
      "Trimming is a property of **every list-valued caller option**, not of the policy axes",
    );
    statesThat("`normalizedList`");
  });

  it("publishes counts that match the code", () => {
    statesThat(`**${LIST_VALUED.length}** of the **${RECOGNIZED_OPTION_KEYS.size}** option keys`);
    statesThat(`**${ROUTED.length}** of them route through the choke point`);
  });

  it("states the structural exception and the out-of-class list by name", () => {
    statesThat(
      "`suppressReasons` is the one structural exception. Its entries are OBJECTS, " +
        "so there is no single value for a list-level normalizer to trim",
    );
    statesThat("the identical trim to each field through the shared `trimListValue` helper");
    statesThat("`enrichers` is out of class. It is the tenth list-valued key");
  });
});
