import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * LINK-ltyjctpf — the ratchet behind [`docs/guarantees.md`](../../../docs/guarantees.md).
 *
 * `LINK-zsbeqtcr` was an unqualified "inspect() never throws" that was false for
 * non-string input and had shipped for weeks, because nothing in the repository
 * could contradict it. The register enumerates every such claim; this test is
 * what stops the enumeration going stale the moment it is written.
 *
 * Three assertions, in increasing order of how much they cost to satisfy:
 *
 *   1. CLAIM BUDGET — the per-file count of guarantee-word lines matches the
 *      register's budget table. Writing a new "never" fails the build until the
 *      author pins, qualifies, or classifies it. This is the whole mechanism:
 *      it moves the triage to authoring time, where the author still knows
 *      whether the code actually does what the sentence says.
 *   2. PIN INTEGRITY — every test path the register names exists.
 *   3. EXEMPLAR COVERAGE — every negative exemplar in the §G audit appears in
 *      at least one test file.
 *
 * Deliberately NOT asserted: that a named test still tests what the register
 * says it does. No regex can check that, and pretending otherwise would put a
 * second unpinned guarantee inside the guarantee register.
 */

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const REGISTER_PATH = join(REPO_ROOT, "docs", "guarantees.md");
const register = readFileSync(REGISTER_PATH, "utf8");

/**
 * The words that make a sentence a promise. Matched case-insensitively and on
 * word boundaries, per line — the same shape a reviewer would grep for.
 */
const GUARANTEE_WORDS =
  /\b(never|always|unconditional(?:ly)?|guarantees?|guaranteed|invariants?)\b/i;

/** The register quotes the claims it tracks, so it is exempt from its own budget. */
const SELF = "docs/guarantees.md";

function claimFiles(): string[] {
  const docs = readdirSync(join(REPO_ROOT, "docs"))
    .filter((name) => name.endsWith(".md"))
    .map((name) => `docs/${name}`)
    .filter((path) => path !== SELF)
    .sort();
  const packages = readdirSync(join(REPO_ROOT, "packages"))
    .map((name) => `packages/${name}/README.md`)
    .filter((path) => existsSync(join(REPO_ROOT, path)))
    .sort();
  return [...docs, "README.md", ...packages];
}

function countClaimLines(path: string): number {
  return readFileSync(join(REPO_ROOT, path), "utf8")
    .split("\n")
    .filter((line) => GUARANTEE_WORDS.test(line)).length;
}

/** Parse the budget table: rows look like `| \`docs/scoring.md\` | 5 |`. */
function budgetTable(): Map<string, number> {
  const section = register.slice(register.search(/^### Claim budget$/m));
  const rows = [...section.matchAll(/^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|$/gm)];
  return new Map(rows.map((m) => [m[1] as string, Number(m[2])]));
}

describe("guarantee register — claim budget (LINK-ltyjctpf)", () => {
  const budget = budgetTable();
  const files = claimFiles();

  it("parses a non-empty budget table (guards against a silently empty sweep)", () => {
    expect(budget.size).toBeGreaterThan(0);
    expect(files.length).toBeGreaterThan(0);
  });

  it("budgets exactly the files that are scanned — no file drifts out of scope", () => {
    expect([...budget.keys()].sort()).toEqual([...files].sort());
  });

  it.each(claimFiles())("%s matches its budgeted claim count", (path) => {
    const actual = countClaimLines(path);
    const budgeted = budget.get(path);
    expect(
      actual,
      `${path} has ${actual} guarantee-word line(s), register says ${budgeted}. ` +
        "Pin the new claim with a test, qualify the prose, or classify it under " +
        "docs/guarantees.md §H — then update the budget.",
    ).toBe(budgeted);
  });
});

describe("guarantee register — pin integrity", () => {
  // Test paths appear in backticks in the `Pinned by` column; a cell may name
  // more than one, and C4's cell is a prose `type-level` note instead.
  const pinnedPaths = [...register.matchAll(/`(packages\/[\w./-]+\.test\.ts)`/g)].map(
    (m) => m[1] as string,
  );

  it("names test files at all (guards against a silently empty sweep)", () => {
    expect(new Set(pinnedPaths).size).toBeGreaterThan(15);
  });

  it.each([...new Set(pinnedPaths)])("%s exists", (path) => {
    expect(existsSync(join(REPO_ROOT, path)), `${path} is named in the register but missing`).toBe(
      true,
    );
  });
});

describe("guarantee register — §G exemplar coverage", () => {
  function testSuiteText(): string {
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const p = join(dir, entry.name);
        return entry.isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
      });
    return readdirSync(join(REPO_ROOT, "packages"))
      .map((name) => join(REPO_ROOT, "packages", name, "test"))
      .filter((dir) => existsSync(dir))
      .flatMap(walk)
      .map((file) => readFileSync(file, "utf8"))
      .join("\n");
  }

  // The §G table's first column: `| \`exemplar\` | claim it pins |`
  const section = register.slice(register.search(/^## G\. Detector precision claims$/m));
  const exemplars = [...section.matchAll(/^\|\s*`([^`]+)`\s*\|\s*[^|]+\|$/gm)].map(
    (m) => m[1] as string,
  );
  const suite = testSuiteText();

  it("parses the exemplar table (guards against a silently empty sweep)", () => {
    expect(exemplars.length).toBeGreaterThan(10);
    expect(suite.length).toBeGreaterThan(0);
  });

  it.each(exemplars)("%s appears in the test suite", (exemplar) => {
    expect(
      suite.includes(exemplar),
      `docs/guarantees.md §G cites ${exemplar} as a pinned precision exemplar, ` +
        "but no test mentions it. Either add the case or drop the row.",
    ).toBe(true);
  });
});
