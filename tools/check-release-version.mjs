/**
 * `node tools/check-release-version.mjs <tag>` — refuses a release whose tag and
 * manifests disagree (LINK-geygvedm).
 *
 * WHY THIS EXISTS. `pnpm publish` rewrites every `workspace:*` dependency to the
 * exact version of the workspace package it resolves to, at pack time. Measured,
 * not assumed: packing `@linklint/cli` at `0.1.0-dev.0` yields
 * `"dependencies": { "linklint": "0.1.0-dev.0" }` in the tarball. Two failures
 * follow from that, and both are unrecoverable once published:
 *
 *   1. If the manifests are not in lockstep, a dependent ships pinned to a
 *      `linklint` version that was never published. The install breaks for
 *      everyone, and npm versions are immutable — the only fix is a new release.
 *   2. If the tag and the manifests disagree, `v0.2.0` publishes 0.1.0. The tag
 *      then names a release that does not exist at the registry.
 *
 * Both are cheap to catch here and expensive to catch afterwards, which is the
 * whole argument for a pre-publish gate rather than a post-publish check.
 *
 * The tag may carry a leading `v`; nothing else about it is reinterpreted.
 * Exit 0 agreement, exit 1 disagreement, exit 2 the check could not run — the
 * same three-way convention as `check-upstream.ts` and `audit-dependencies.ts`,
 * because "could not check" must never read as "all clear".
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "packages");

/** Strip the one decoration a tag is allowed to carry. */
export const versionFromTag = (tag) => (tag.startsWith("v") ? tag.slice(1) : tag);

/**
 * The decision, separated from the filesystem and from `process.exit` so it can
 * be pinned by `tests/unit/check-release-version.test.ts` without a fixture tree.
 *
 * @param tag       the release tag, `v`-prefix optional
 * @param manifests `{ name, version }` for every workspace package
 * @returns `{ code, message }` — code 0 agreement, 1 disagreement, 2 unrunnable
 */
export function checkReleaseVersion(tag, manifests) {
  if (!tag) return { code: 2, message: "usage: check-release-version.mjs <tag>" };
  if (manifests.length === 0) return { code: 2, message: "no packages found" };

  const expected = versionFromTag(tag);
  const agrees = (m) => m.version === expected;

  if (manifests.every(agrees)) {
    return { code: 0, message: `tag ${tag}: all ${manifests.length} packages at ${expected}` };
  }

  const detail = manifests.map((m) => `  ${agrees(m) ? " " : "!"} ${m.name} ${m.version}`).join("\n");
  return {
    code: 1,
    message:
      `tag ${tag} expects every package at ${expected}, but they do not all agree:\n${detail}\n` +
      `\nEvery package must be at ${expected} before tagging: pnpm rewrites each\n` +
      `\`workspace:*\` to the exact version at pack time, so a drifted manifest\n` +
      `publishes a dependent pinned to a \`linklint\` that does not exist.`,
  };
}

/** Read `{ name, version }` for every package in the workspace. */
export function readManifests(packagesDir = PACKAGES_DIR) {
  return readdirSync(packagesDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const { name, version } = JSON.parse(
        readFileSync(join(packagesDir, entry.name, "package.json"), "utf8"),
      );
      return { name, version };
    });
}

// CLI. Skipped on import, so the test can reach the functions above without
// running the check or exiting the process.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let manifests;
  try {
    manifests = readManifests();
  } catch (error) {
    console.error(`could not read the workspace manifests: ${error.message}`);
    process.exit(2);
  }
  const { code, message } = checkReleaseVersion(process.argv[2], manifests);
  (code === 0 ? console.log : console.error)(message);
  process.exit(code);
}
