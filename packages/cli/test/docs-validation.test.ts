import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { USAGE } from "../src/cli.js";

// The CLI flag surface is documented twice — the root README's flag table and
// the package README's — and neither is generated. `--help` is the third copy
// and the only one users see at the moment of use. Pin all three to each other
// (LINK-zyvfmjfe scope item 3). They matched on a spot-check, which is exactly
// when pinning is cheap.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...p: string[]) => readFileSync(join(REPO_ROOT, ...p), "utf8");

const rootReadme = read("README.md");
const cliReadme = read("packages", "cli", "README.md");

// Flags documented in --help, minus the two that are universal and not part of
// the behavioral surface the README tables describe.
const SELF_DESCRIBING = new Set(["--help", "--version"]);

function flagsIn(text: string): Set<string> {
  return new Set([...text.matchAll(/(--[a-z][a-z-]*)/g)].map((m) => m[1] as string));
}

const helpFlags = [...flagsIn(USAGE)].filter((f) => !SELF_DESCRIBING.has(f)).sort();

describe("the CLI flag surface matches its documentation", () => {
  it("--help advertises the expected number of behavioral flags", () => {
    // Floor guards the extractor: if USAGE is restructured so the regex stops
    // matching, this fails instead of the suite silently covering nothing.
    expect(helpFlags.length).toBeGreaterThanOrEqual(9);
  });

  it.each(helpFlags)("%s is in the root README flag table", (flag) => {
    expect(flagsIn(rootReadme).has(flag)).toBe(true);
  });

  it.each(helpFlags)("%s is in the CLI package README flag table", (flag) => {
    expect(flagsIn(cliReadme).has(flag)).toBe(true);
  });

  // The reverse direction catches stale removals: a flag dropped from the CLI
  // but left in the prose is worse than one merely undocumented, because a
  // reader will try it and get a usage error.
  it.each([...flagsIn(cliReadme)].sort())("documented flag %s still exists in --help", (flag) => {
    expect(USAGE).toContain(flag);
  });
});
