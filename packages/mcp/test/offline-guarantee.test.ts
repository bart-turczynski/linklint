import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";

/**
 * `packages/mcp/README.md` publishes a `## Guarantees` section: **no outbound
 * network**, **no telemetry** (v1, FR-MCP-2), and **read-only** tools
 * (`readOnlyHint`). None of the three had a test before LINK-ltyjctpf — the
 * annotations were set in `tools/index.ts` and never asserted, and nothing
 * stopped an HTTP transport from being wired in.
 *
 * The MCP server is a stdio process by design: it speaks over stdin/stdout, so
 * the guarantee is that no *other* channel exists. The SDK ships HTTP/SSE
 * transports in the same package, so the import scan names them explicitly
 * rather than trusting the dependency list.
 */

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = resolve(here, "../src");
const packageJsonPath = resolve(here, "../package.json");
const readmePath = resolve(here, "../README.md");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
  });
}

describe("@linklint/mcp — no outbound network, no telemetry (published guarantee)", () => {
  const sources = walk(srcDir);

  it("finds source files to scan (guards against a silently empty sweep)", () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it("imports no network or IPC module", () => {
    const forbidden =
      /from\s+["'](node:)?(net|tls|http|https|http2|dgram|dns|child_process|worker_threads|cluster|inspector)["']/;
    const offenders = sources.filter((f) => forbidden.test(readFileSync(f, "utf8")));
    expect(offenders, `network/IPC imports found: ${offenders.join(", ")}`).toEqual([]);
  });

  // The SDK's networked transports live in the dependency the server already
  // has, so the dependency allowlist below cannot catch them.
  it("imports no networked MCP transport (stdio only)", () => {
    const forbidden = /server\/(streamableHttp|sse)\.js/;
    const offenders = sources.filter((f) => forbidden.test(readFileSync(f, "utf8")));
    expect(offenders, `networked MCP transports found: ${offenders.join(", ")}`).toEqual([]);
  });

  it("calls no ambient network global", () => {
    const forbidden = /\b(fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon)\s*\(/;
    const offenders = sources.filter((f) => forbidden.test(readFileSync(f, "utf8")));
    expect(offenders, `ambient network calls found: ${offenders.join(", ")}`).toEqual([]);
  });

  it("pins its dependency set", () => {
    const pkg = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
      dependencies?: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies ?? {}).sort()).toEqual([
      "@modelcontextprotocol/sdk",
      "linklint",
      "zod",
    ]);
  });

  it("still publishes the guarantees it is pinning", () => {
    const readme = readFileSync(readmePath, "utf8");
    expect(readme).toContain("## Guarantees");
    expect(readme).toContain("**No outbound network**");
    expect(readme).toContain("no telemetry");
    expect(readme).toContain("**Read-only**");
  });
});

describe("@linklint/mcp — every tool is annotated read-only and closed-world", () => {
  let client: Client;

  beforeAll(async () => {
    const server = createServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: "linklint-guarantee-test", version: "0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
  });

  afterAll(async () => {
    await client.close();
  });

  // Asserted over the wire, not over the source literal: the annotation only
  // means anything if the client actually receives it.
  it("advertises readOnlyHint and openWorldHint on every registered tool", async () => {
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(true);
      expect(tool.annotations?.openWorldHint, tool.name).toBe(false);
    }
  });
});
