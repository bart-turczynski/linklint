import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CLI_VERSION } from "@linklint/cli";

describe("CLI_VERSION is sourced from package.json", () => {
  const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));

  it("equals the version in packages/cli/package.json", () => {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    expect(CLI_VERSION).toBe(pkg.version);
  });

  it("does not reintroduce a hardcoded version literal", () => {
    const sourcePath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("createRequire(import.meta.url)");
    expect(source).not.toMatch(/CLI_VERSION\s*=\s*["'][^"']+["']/);
  });
});
