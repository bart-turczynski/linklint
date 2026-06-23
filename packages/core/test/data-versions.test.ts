import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { DATA_VERSIONS } from "../src/data/versions.js";

const require_ = createRequire(import.meta.url);

/**
 * Resolve the installed version of a dependency relative to THIS test module
 * (not process.cwd()). Export maps block `require('<pkg>/package.json')`, so we
 * resolve the package entry point and walk parent dirs to the first
 * package.json whose `name` matches the package.
 */
function installedVersion(pkg: string): string {
  let dir = dirname(require_.resolve(pkg));
  // Walk up to the filesystem root looking for the owning package.json.
  for (;;) {
    const candidate = join(dir, "package.json");
    try {
      const manifest = JSON.parse(readFileSync(candidate, "utf8")) as {
        name?: string;
        version?: string;
      };
      if (manifest.name === pkg && typeof manifest.version === "string") {
        return manifest.version;
      }
    } catch {
      // No package.json here (or unreadable); keep walking up.
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`could not resolve installed version for ${pkg}`);
}

// Lock the data version stamps that mirror installed dependency releases. These
// carry hand-maintained `<name>@<version>` strings; this test ensures they
// track the actually-installed package versions so reproducibility stamps never
// silently lie.
describe("DATA_VERSIONS dependency stamps match installed versions", () => {
  it.each([
    { key: "publicSuffixList", stamp: DATA_VERSIONS.publicSuffixList, pkg: "tldts" },
    { key: "idna", stamp: DATA_VERSIONS.idna, pkg: "tr46" },
  ])("$key stamp ($stamp) matches the installed $pkg version", ({ stamp, pkg }) => {
    const atIndex = stamp.lastIndexOf("@");
    expect(atIndex).toBeGreaterThan(0);
    const name = stamp.slice(0, atIndex);
    const version = stamp.slice(atIndex + 1);
    expect(name).toBe(pkg);
    expect(version).toBe(installedVersion(pkg));
  });
});
