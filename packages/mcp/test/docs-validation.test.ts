import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECK_DOMAIN_INPUT, CHECK_URL_INPUT } from "../src/tools/check.js";

// Every MCP tool parameter is documented, and the documented tool table names
// only real parameters (LINK-zyvfmjfe scope item 3). The MCP surface is what an
// agent reads to decide how to call the tool, so a stale parameter name here is
// a failed call rather than a cosmetic doc bug.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...p: string[]) => readFileSync(join(REPO_ROOT, ...p), "utf8");

const mcpReadme = read("packages", "mcp", "README.md");
const rootReadme = read("README.md");

const TOOLS = [
  ["check_url", CHECK_URL_INPUT],
  ["check_domain", CHECK_DOMAIN_INPUT],
] as const;

describe("the MCP tool surface matches its documentation", () => {
  it("both tools expose the expected shape", () => {
    expect(Object.keys(CHECK_URL_INPUT).sort()).toEqual(["agentMode", "url"]);
    expect(Object.keys(CHECK_DOMAIN_INPUT).sort()).toEqual(["agentMode", "domain"]);
  });

  it.each(TOOLS.map(([name]) => name))("tool %s is named in both READMEs", (name) => {
    expect(mcpReadme).toContain(name);
    expect(rootReadme).toContain(name);
  });

  const params = TOOLS.flatMap(([name, schema]) =>
    Object.keys(schema).map((key) => [name, key] as const),
  );

  it.each(params)("%s parameter %s is documented in the MCP README", (_tool, key) => {
    expect(mcpReadme).toContain(key);
  });

  // Reverse direction: the tool table in the MCP README states each tool's
  // parameter object inline. Every identifier it names must be a real key.
  it.each(TOOLS.map(([name, schema]) => [name, schema] as const))(
    "the %s row names only real parameters",
    (name, schema) => {
      const row = mcpReadme.split("\n").find((l) => l.includes(`\`${name}\``) && l.includes("|"));
      expect(row).toBeDefined();
      const cell = (row as string).match(/`\{([^}]*)\}`/);
      expect(cell).not.toBeNull();
      const named = [...(cell?.[1] as string).matchAll(/([a-zA-Z][a-zA-Z0-9]*)\??:/g)].map(
        (m) => m[1] as string,
      );
      expect(named.length).toBeGreaterThanOrEqual(2);
      for (const key of named) expect(schema).toHaveProperty(key);
    },
  );
});
