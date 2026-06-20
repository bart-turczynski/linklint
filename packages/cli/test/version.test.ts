import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CLI_VERSION } from "@linklint/cli";

// Lock the hardcoded CLI_VERSION (kept in sync with package.json by hand) so
// any drift between the source constant and the published package version
// fails CI instead of silently shipping a wrong version string.
describe("CLI_VERSION stays in sync with package.json", () => {
  it("equals the version in packages/cli/package.json", () => {
    const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    expect(CLI_VERSION).toBe(pkg.version);
  });
});
