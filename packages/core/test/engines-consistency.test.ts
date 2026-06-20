import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Resolve paths relative to THIS test module (not process.cwd()) so the
// drift-lock holds regardless of where the test runner is invoked from.
const thisDir = dirname(fileURLToPath(import.meta.url));
// packages/core/test -> repo root is three levels up.
const repoRoot = join(thisDir, "..", "..", "..");

function enginesNode(manifestPath: string): string {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    engines?: { node?: string };
  };
  return manifest.engines?.node ?? "";
}

// Lock the Node support contract to a single value across the root manifest and
// every published package. The decided contract is Node >=24 (matching CI and
// @types/node). Any future drift between these manifests fails CI here.
describe("engines.node is consistent across all manifests", () => {
  const EXPECTED = ">=24";

  const manifests = {
    root: join(repoRoot, "package.json"),
    core: join(repoRoot, "packages", "core", "package.json"),
    cli: join(repoRoot, "packages", "cli", "package.json"),
    mcp: join(repoRoot, "packages", "mcp", "package.json"),
  };

  it.each(Object.entries(manifests))(
    "%s manifest declares engines.node === %s",
    (_name, manifestPath) => {
      expect(enginesNode(manifestPath)).toBe(EXPECTED);
    },
  );

  it("all four manifests agree on engines.node", () => {
    const values = Object.values(manifests).map(enginesNode);
    const unique = new Set(values);
    expect(unique.size).toBe(1);
    expect([...unique][0]).toBe(EXPECTED);
  });
});
