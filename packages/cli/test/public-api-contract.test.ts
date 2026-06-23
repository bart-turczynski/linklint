import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as cli from "../src/index.js";

const thisDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(thisDir, "..", "..", "..");

describe("@linklint/cli public library API", () => {
  it("exposes exactly the supported testable CLI helpers", () => {
    expect(Object.keys(cli).sort()).toEqual(
      [
        "CLI_VERSION",
        "SEVERITY_ORDER",
        "USAGE",
        "VALID_FAIL_ON",
        "UsageError",
        "isSeverity",
        "main",
        "parseCli",
        "parseUrlLines",
        "renderJson",
        "renderResults",
        "resolveExitCode",
        "run",
        "severityRank",
      ].sort(),
    );
  });

  it("only publishes the root library entry point; the bin stays separate", () => {
    const manifest = JSON.parse(
      readFileSync(join(repoRoot, "packages", "cli", "package.json"), "utf8"),
    ) as {
      bin: Record<string, string>;
      exports: Record<string, Record<string, string>>;
    };

    expect(manifest.bin).toEqual({ linklint: "./dist/cli.js" });
    expect(Object.keys(manifest.exports)).toEqual(["."]);
    expect(Object.keys(manifest.exports["."] ?? {})).toEqual(["types", "default"]);
  });
});
