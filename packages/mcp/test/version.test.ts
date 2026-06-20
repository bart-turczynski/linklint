import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SERVER_VERSION } from "../src/server.js";

// Lock the hardcoded SERVER_VERSION (kept in sync with package.json by hand)
// so any drift between the source constant and the published package version
// fails CI instead of silently advertising a wrong version over MCP.
describe("SERVER_VERSION stays in sync with package.json", () => {
  it("equals the version in packages/mcp/package.json", () => {
    const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    expect(SERVER_VERSION).toBe(pkg.version);
  });
});
