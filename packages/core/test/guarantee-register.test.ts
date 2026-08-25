import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT, packageReadmes, sweptDocs } from "./doc-sweep.js";

/**
 * LINK-ltyjctpf — the ratchet behind [`docs/guarantees.md`](../../../docs/guarantees.md).
 *
 * `LINK-zsbeqtcr` was an unqualified "inspect() never throws" that was false for
 * non-string input and had shipped for weeks, because nothing in the repository
 * could contradict it. The register enumerates every such claim; this test is
 * what stops the enumeration going stale the moment it is written.
 *
 * Four assertions, in increasing order of how much they cost to satisfy:
 *
 *   1. CLAIM BUDGET — the per-file count of guarantee-word lines matches the
 *      register's budget table. Writing a new "never" fails the build until the
 *      author pins, qualifies, or classifies it. This is the whole mechanism:
 *      it moves the triage to authoring time, where the author still knows
 *      whether the code actually does what the sentence says.
 *   2. PIN INTEGRITY — every test path the register names exists.
 *   3. EXEMPLAR COVERAGE — every negative exemplar in the §G audit appears in
 *      at least one test file.
 *   4. SWEEP SHAPE (LINK-umlssdan) — the set (1) scans is what the register
 *      says it is: `docs/` at any depth, and `packages/` one level because the
 *      workspace glob is one level. Without this the budget's completeness is
 *      a fact about the current tree rather than about the walk.
 *
 * Deliberately NOT asserted: that a named test still tests what the register
 * says it does. No regex can check that, and pretending otherwise would put a
 * second unpinned guarantee inside the guarantee register.
 */

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

/**
 * The sweep itself lives in `./doc-sweep.ts` (LINK-fmmzkmas) so that
 * `doc-links.test.ts` walks the SAME set rather than a parallel one that can
 * drift. `sweptDocs` is recursive (LINK-umlssdan) and `packageReadmes` is one
 * level deep because the workspace glob is; both are pinned against a fixture
 * tree by the sweep-shape block at the bottom of this file.
 */
function claimFiles(): string[] {
  const docs = sweptDocs(join(REPO_ROOT, "docs")).filter((path) => path !== SELF);
  return [...docs, "README.md", ...packageReadmes(REPO_ROOT)];
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

/**
 * The `packages:` list from `pnpm-workspace.yaml`, read without a YAML
 * dependency: the lines under the key until the next top-level key.
 */
function workspacePackageGlobs(): string[] {
  const yaml = readFileSync(join(REPO_ROOT, "pnpm-workspace.yaml"), "utf8");
  const start = yaml.search(/^packages:\s*$/m);
  if (start < 0) return [];
  const globs: string[] = [];
  for (const line of yaml.slice(start).split("\n").slice(1)) {
    const match = /^\s+-\s*"?([^"\s]+)"?\s*$/.exec(line);
    if (match) globs.push(match[1] as string);
    else if (line.trim() !== "") break;
  }
  return globs;
}

/**
 * "budgets exactly the files that are scanned", evaluated against an arbitrary
 * root — the same sorted set equality the live assertion applies to `docs/`,
 * so the sweep-shape pins below exercise the real comparison and not a
 * paraphrase of it.
 */
function budgetAccepts(keys: string[], root: string): boolean {
  const a = [...keys].sort();
  const b = sweptDocs(root).sort();
  return a.length === b.length && a.every((key, i) => key === b[i]);
}

/**
 * LINK-umlssdan — the SHAPE of the sweep, pinned against a fixture tree.
 *
 * The claim budget above is the guard the rest of the repository leans on, and
 * until LINK-umlssdan its coverage of `docs/` was total only because `docs/`
 * has no subdirectories. That is a property of the tree, not of the walk, and
 * nothing observable through the live tree can tell the two apart — an
 * assertion made against `docs/` as it stands passes whatever the walk does.
 * The fixture supplies the subdirectory the repository does not have, so both
 * halves are pinned rather than assumed:
 *
 *   (a) a `.md` in a subdirectory IS swept — it used to be invisible, and a
 *       `never` line in it left the suite green (measured: 90/90 passing);
 *   (b) and it must therefore be BUDGETED — a budget row for it used to FAIL
 *       "budgets exactly the files that are scanned", so the obvious workaround
 *       was refused too. Now the budget that omits it is the one that fails.
 *
 * The package walk's depth is pinned separately, against the workspace glob it
 * mirrors, so that one level is a construction and not a second accident.
 */
describe("guarantee register — sweep shape (LINK-umlssdan)", () => {
  const NESTED = "docs/worklog/nested.md";
  let fixture = "";

  beforeAll(() => {
    fixture = mkdtempSync(join(tmpdir(), "linklint-sweep-"));
    writeFileSync(join(fixture, "top.md"), "A top-level claim: this never fires.\n");
    mkdirSync(join(fixture, "worklog"));
    writeFileSync(join(fixture, "worklog", "nested.md"), "A nested claim: this never fires.\n");
    mkdirSync(join(fixture, "deep", "er"), { recursive: true });
    writeFileSync(join(fixture, "deep", "er", "deeper.md"), "Deeper: this never fires.\n");
    writeFileSync(join(fixture, "worklog", "notes.txt"), "Not markdown; never swept.\n");
  });

  afterAll(() => {
    if (fixture) rmSync(fixture, { recursive: true, force: true });
  });

  it("the fixture really has the nested file (guards a vacuous pin)", () => {
    expect(existsSync(join(fixture, "worklog", "nested.md"))).toBe(true);
    expect(existsSync(join(fixture, "deep", "er", "deeper.md"))).toBe(true);
    expect(sweptDocs(fixture)).toContain("docs/top.md");
  });

  it("a .md in a docs/ subdirectory is swept, at any depth", () => {
    expect(sweptDocs(fixture)).toEqual(["docs/deep/er/deeper.md", "docs/top.md", NESTED]);
  });

  it("and must be budgeted — a budget that omits it is the one that fails", () => {
    // `budgetAccepts` is the comparison the live assertion makes: the budget's
    // key set against the scanned set, sorted, deep-equal. Both directions, so
    // a walk that regressed to flat reddens here rather than going quiet.
    expect(budgetAccepts(["docs/top.md"], fixture)).toBe(false);
    expect(budgetAccepts(["docs/top.md", NESTED, "docs/deep/er/deeper.md"], fixture)).toBe(true);
  });

  it("the packages walk is one level deep because the workspace glob is", () => {
    // The README sweep reads `packages/` a single level. That is right for the
    // layout `pnpm-workspace.yaml` declares, and wrong the moment the glob
    // gains depth or a second root — so assert the glob rather than the layout.
    expect(
      workspacePackageGlobs(),
      "pnpm-workspace.yaml no longer declares exactly `packages/*`. claimFiles() " +
        "reads packages/ one level deep on the strength of that glob; widen the " +
        "walk to match before changing it.",
    ).toEqual(["packages/*"]);
  });
});
