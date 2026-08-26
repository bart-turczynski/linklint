import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import {
  REASON_CODES,
  REASON_FAMILIES,
  codesInFamily,
  familyFor,
  type ReasonCode,
  type ReasonFamily,
} from "../src/schema/reason-codes.js";
import { REPO_ROOT } from "./doc-sweep.js";

/**
 * LINK-tviundio — reason-code correlation families.
 *
 * The observation that motivated the taxonomy: one edit to a URL can raise
 * several reason codes, and `reasons[]` then reads to a triager as several
 * separate problems when the underlying evidence is one. `apple.com` with its
 * leading `a` replaced by CYRILLIC SMALL LETTER A (U+0430) is the worked case —
 * a single code point, four scoring codes and two informational ones.
 *
 * This block pins the observation itself, before any taxonomy exists, so the
 * partition that follows is anchored on measured behavior rather than on a
 * recollection of it. Under probabilistic-OR the score saturates either way;
 * what the correlation distorts is the explanation, which is the product.
 */

/** `apple.com` with U+0430 in place of the leading ASCII `a`. */
const CYRILLIC_APPLE = "https://аpple.com/";

function codesOf(url: string, options: Parameters<typeof inspect>[1] = {}): string[] {
  return inspect(url, options).reasons.map((r) => r.code);
}

function scoringCodesOf(url: string, options: Parameters<typeof inspect>[1] = {}): string[] {
  return inspect(url, options)
    .reasons.filter((r) => r.weight > 0)
    .map((r) => r.code);
}

describe("one edit, many codes — the correlation the families describe", () => {
  it("the unmodified host is clean, so the whole reason list is attributable to one code point", () => {
    const clean = inspect("https://apple.com/");
    expect(clean.status).toBe("ok");
    expect(clean.reasons).toEqual([]);
    expect(clean.score).toBe(0);
  });

  it("one Cyrillic code point raises exactly four scoring codes", () => {
    expect(scoringCodesOf(CYRILLIC_APPLE)).toEqual([
      "homograph_latin_skeleton",
      "mixed_script",
      "idn_host",
      "homograph_skeleton_collision",
    ]);
  });

  it("the same code point also raises two weight-0 codes, for six reasons off one character", () => {
    expect(codesOf(CYRILLIC_APPLE)).toEqual([
      "homograph_latin_skeleton",
      "mixed_script",
      "idn_host",
      "homograph_skeleton_collision",
      "confusable_char",
      "normalization_delta",
    ]);
  });

  it("saturating aggregation hides the correlation in the score but not in the explanation", () => {
    const result = inspect(CYRILLIC_APPLE);
    expect(result.score).toBe(1);
    expect(result.severity).toBe("critical");
    // A weight-1 code alone already lands here, so the other three move nothing.
    expect(result.reasons.filter((r) => r.weight === 1).length).toBeGreaterThan(0);
  });

  it("one ASCII digit substitution raises two codes on a pure-ASCII host", () => {
    expect(codesOf("https://paypal.com/")).toEqual([]);
    expect(codesOf("https://paypa1.com/")).toEqual(["brand_homoglyph", "ascii_homoglyph"]);
  });

  /**
   * The escape pair behaves differently from the two clusters above and is
   * pinned so the taxonomy is not written against a guess. `encoding_obfuscation`
   * and `percent_encoding_malformed` read the same feature — the percent-escape
   * sequence — but they read it to opposite conclusions, so a single escape
   * raises one or the other rather than both. Codes that share a feature and
   * exclude each other are still correlated evidence: seeing the second tells a
   * triager nothing the first did not already rest on.
   */
  it("one escape raises one of the two escape codes, not both", () => {
    expect(codesOf("https://example.com/a%2fb")).toEqual(["encoding_obfuscation"]);
    expect(codesOf("https://example.com/a%252fb")).toEqual(["encoding_obfuscation"]);
    expect(codesOf("https://example.com/a%2")).toEqual(["percent_encoding_malformed"]);
    expect(codesOf("https://example.com/a%zzb")).toEqual(["percent_encoding_malformed"]);
  });

  /**
   * The other direction, which the tie-break in `docs/reason-codes.md` turns on:
   * escaping one control character raises codes that read the escape AND codes
   * that read the byte it decodes to, so an edit can touch two features at once.
   */
  it("escaping one control character raises codes from more than one feature", () => {
    const codes = codesOf("https://example.com/x?a=1%0d%0aHost:%20evil");
    expect(codes).toContain("encoding_obfuscation");
    expect(codes).toContain("control_char");
    expect(codes).toContain("header_shaped_token");
  });

  it("each of those two features is reachable without the other", () => {
    // An escape that hides a delimiter, with no control byte anywhere.
    expect(codesOf("https://example.com/a%2fb")).toEqual(["encoding_obfuscation"]);
    // A raw control character, with no escape anywhere.
    const raw = codesOf("https://example.com/x?a=1\rHost: evil");
    expect(raw).toContain("control_char");
    expect(raw).not.toContain("encoding_obfuscation");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Drift guard. Same shape as the weights-table guard in `docs-validation.test.ts`
// (COMPLETENESS → VALUE → NO ORPHANS → STATED COUNTS), because the failure mode
// is the same one: a registry and the document a reader consults, coupled by
// nothing, drifting until the document confidently states the wrong thing.
// ─────────────────────────────────────────────────────────────────────────────

const reasonCodesDoc = readFileSync(join(REPO_ROOT, "docs", "reason-codes.md"), "utf8");

const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
const familyIds = Object.keys(REASON_FAMILIES) as ReasonFamily[];
const familyIdSet = new Set<string>(familyIds);
const scoringCodes = registryCodes.filter((code) => REASON_CODES[code].scoring);

/** Flatten hard wraps and list markers so a substring match is not silently vacuous. */
function flatten(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(/^\s*(?:[-*]|>)\s*/, ""))
    .join(" ")
    .replace(/\s+/g, " ");
}

/** The `### The partition` section of the doc, and only it. */
function partitionSection(): string {
  const start = reasonCodesDoc.indexOf("### The partition");
  expect(start, "docs/reason-codes.md has no partition section").toBeGreaterThan(-1);
  const next = reasonCodesDoc.indexOf("\n### ", start + 1);
  return reasonCodesDoc.slice(start, next === -1 ? undefined : next);
}

const partition = partitionSection();

// Rows: | `family` | Reads … | `code`, `code` |
interface DocRow {
  readonly reads: string;
  readonly codes: string[];
}
const docRows = new Map<string, DocRow>(
  [...partition.matchAll(/^\|\s*`([a-z_]+)`\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|$/gm)].map((m) => [
    m[1] as string,
    {
      reads: m[2] as string,
      codes: [...(m[3] as string).matchAll(/`([a-z_]+)`/g)].map((c) => c[1] as string),
    },
  ]),
);

describe("reason-code families — registry totality (LINK-tviundio)", () => {
  // 1. TOTALITY, SCORING — the assertion the ticket asks for by name. A scoring
  //    code with no family is a code whose evidence nobody classified, which is
  //    exactly the state the taxonomy exists to end.
  it.each(scoringCodes)("scoring code %s declares a family", (code) => {
    const family = REASON_CODES[code].family as string | undefined;
    expect(family, `${code} declares no family`).toBeDefined();
    expect(familyIdSet.has(family as string), `${code} declares unknown family ${family}`).toBe(
      true,
    );
  });

  // 2. TOTALITY, WHOLE REGISTRY — weight-0 and policy codes are classified too:
  //    a triager reads them in the same list, and `normalization_delta` is the
  //    single most co-raised code in the registry.
  it.each(registryCodes)("registry code %s declares a known family", (code) => {
    expect(familyIdSet.has(REASON_CODES[code].family)).toBe(true);
  });

  // 3. NO EMPTY FAMILY — a declared id with no members is a taxonomy row left
  //    behind by a rename, and it would make the partition look wider than it is.
  it.each(familyIds)("family %s has at least one member", (family) => {
    expect(codesInFamily(family).length).toBeGreaterThan(0);
  });

  // 4. PARTITION — the families cover the registry exactly once each, so
  //    `codesInFamily` over every id reconstructs the key set with no code
  //    counted twice and none dropped.
  it("the families partition the registry", () => {
    const covered = familyIds.flatMap((family) => codesInFamily(family));
    expect(covered.length).toBe(registryCodes.length);
    expect([...covered].sort()).toEqual([...registryCodes].sort());
  });

  it("familyFor agrees with the registry entry for every code", () => {
    for (const code of registryCodes) expect(familyFor(code)).toBe(REASON_CODES[code].family);
  });
});

describe("reason-code families — docs/reason-codes.md stays in sync", () => {
  it("parses a non-empty partition table (guards a silently blind regex)", () => {
    expect(docRows.size).toBeGreaterThan(0);
  });

  // 5. COMPLETENESS — every declared family has a row.
  it.each(familyIds)("family %s has a documented row", (family) => {
    expect(docRows.has(family)).toBe(true);
  });

  // 6. VALUE — the row's member list equals the registry's, in registry order.
  //    Presence alone would let a re-parented code ship against a stale row,
  //    which is worse than an omission: the reader gets a confident wrong answer.
  it.each(familyIds)("documented members of %s equal the registry members", (family) => {
    expect(docRows.get(family)?.codes).toEqual(codesInFamily(family) as string[]);
  });

  // 7. VALUE — the `Reads` column restates the registry description verbatim, so
  //    a reworded feature cannot mean two things in two places.
  it.each(familyIds)("documented description of %s equals the registry description", (family) => {
    expect(docRows.get(family)?.reads).toBe(REASON_FAMILIES[family]);
  });

  // 8. NO ORPHANS, BOTH DIRECTIONS — a renamed family or a deleted code must not
  //    survive as a table row.
  it.each([...docRows.keys()])("documented family %s is a real family id", (family) => {
    expect(familyIdSet.has(family)).toBe(true);
  });

  it("every code named in the table is a real registry code", () => {
    for (const [family, row] of docRows)
      for (const code of row.codes)
        expect(REASON_CODES, `${family} names unknown code ${code}`).toHaveProperty(code);
  });

  // 9. STATED COUNTS — the two numbers a reader trusts without counting rows.
  it("the prose totals match the registry", () => {
    expect(partition).toContain(
      `${familyIds.length} families over the ${registryCodes.length} registered codes`,
    );
  });

  // 10. THE RULE IS STATED — the partition is the cheap half; the rule is what
  //     lets the next author place a code without guessing. Matched over
  //     flattened prose because every one of these clauses is hard-wrapped in
  //     the source, and a raw substring match would find none of them.
  it("states the placement rule, its two proofs and the tie-break", () => {
    const flat = flatten(reasonCodesDoc);
    expect(flat).toContain(
      "A code belongs to the family of the feature its detector reads to decide whether to fire.",
    );
    expect(flat).toContain("If that edit can raise both codes, they read the same feature");
    expect(flat).toContain(
      "If raising the second code takes a further edit to a different feature, the two do not share a family.",
    );
    expect(flat).toContain(
      "Place such a code by the feature that carries the deception — the one that makes the finding a finding rather than a fact.",
    );
    expect(flat).toContain("Mutual exclusion is a strong form of dependence");
  });

  it("records that the family is registry-only, so no stamp moved", () => {
    const flat = flatten(reasonCodesDoc);
    expect(flat).toContain("It is not a field on the serialized `InspectResult`");
    expect(flat).toContain("`WEIGHTS_VERSION` stays put");
  });
});

describe("reason-code families — the grouping the taxonomy buys", () => {
  it("collapses six reasons off one code point into two features", () => {
    const families = inspect(CYRILLIC_APPLE).reasons.map((r) => familyFor(r.code as ReasonCode));
    expect(families).toHaveLength(6);
    expect(new Set(families)).toEqual(new Set(["character_identity", "idn_form"]));
  });

  it("collapses the digit-substitution pair into one feature", () => {
    const families = new Set(
      inspect("https://paypa1.com/").reasons.map((r) => familyFor(r.code as ReasonCode)),
    );
    expect([...families]).toEqual(["character_identity"]);
  });

  it("keeps two genuinely separate features separate on one input", () => {
    // An escape AND the byte it decodes to — two features, so two families.
    const families = new Set(
      inspect("https://example.com/x?a=1%0d%0aHost:%20evil").reasons.map((r) =>
        familyFor(r.code as ReasonCode),
      ),
    );
    expect([...families].sort()).toEqual(["decoded_bytes", "percent_escapes"]);
  });
});
