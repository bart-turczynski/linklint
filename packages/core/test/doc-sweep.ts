import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The ONE walk over the repository's prose.
 *
 * Extracted from `guarantee-register.test.ts` (LINK-fmmzkmas) so that the link
 * checker in `doc-links.test.ts` sweeps exactly the set the claim budget
 * sweeps, rather than a second walk that can drift from it. That drift is the
 * defect LINK-umlssdan fixed once already: the budget's coverage of `docs/` was
 * total by accident, because the walk was flat and `docs/` happened to be flat
 * too. A parallel walker reintroduces the same class of accident — a file that
 * one guard sees and the other does not, with nothing to say which is right.
 *
 * Both functions here are pinned against a fixture tree by the sweep-shape
 * block at the bottom of `guarantee-register.test.ts`.
 */

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/**
 * Every `.md` under `root`, at ANY depth, returned as a `docs/`-prefixed
 * repo-relative path.
 *
 * Taken as a function of its root so the walk itself can be pinned against a
 * fixture tree. `docs/` has no subdirectories in this repository today, so any
 * claim about them asserted through the live tree would be vacuous — it would
 * pass whatever the walk does.
 *
 * RECURSIVE (LINK-umlssdan). It was flat until then, and `docs/` happened to be
 * flat too, so the ratchet's coverage was total by accident: one
 * `mkdir docs/whatever` and new prose would have stopped being swept with the
 * suite staying green — and a budget row naming the new file would have failed
 * the keys assertion rather than fixing it. Every `.md` at any depth is
 * returned, so a subdirectory file is swept AND budgetable.
 */
export function sweptDocs(root: string): string[] {
  const walk = (dir: string, prefix: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory()
        ? walk(join(dir, entry.name), `${prefix}${entry.name}/`)
        : entry.name.endsWith(".md")
          ? [`${prefix}${entry.name}`]
          : [],
    );
  return walk(root, "docs/").sort();
}

/**
 * The published `README.md` of every workspace package, repo-relative.
 *
 * One level deep, and correct by construction rather than by accident:
 * `pnpm-workspace.yaml` declares `packages/*`, so a workspace package is always
 * exactly one directory under `packages/`. That glob is asserted by the
 * sweep-shape block in `guarantee-register.test.ts`, so a change to it reddens
 * there instead of silently narrowing the sweep. Markdown inside a package
 * other than its `README.md` is out of scope by design — the sweep covers the
 * published READMEs.
 */
export function packageReadmes(repoRoot: string): string[] {
  return readdirSync(join(repoRoot, "packages"))
    .map((name) => `packages/${name}/README.md`)
    .filter((path) => existsSync(join(repoRoot, path)))
    .sort();
}
