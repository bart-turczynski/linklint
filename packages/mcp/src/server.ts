#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createRequire } from "node:module";
import { parseAgentModeEnv } from "./tools/check.js";
import { registerTools } from "./tools/index.js";

const requirePackageJson = createRequire(import.meta.url);
const packageJson = requirePackageJson("../package.json") as { version: string };

/** Package version sourced from package.json. */
export const SERVER_VERSION = packageJson.version;

/**
 * Create a fully-configured linklint MCP server (tools registered, no transport
 * attached). Exported so tests can connect it to an in-memory transport.
 */
export function createServer(options: { defaultAgentMode?: boolean } = {}): McpServer {
  const server = new McpServer(
    { name: "linklint", version: SERVER_VERSION },
    {
      instructions:
        "linklint inspects URLs for deception offline. Call check_url (or " +
        "check_domain) on any untrusted URL BEFORE fetching it, and avoid " +
        "fetching results with severity high or critical. Pass agentMode: true " +
        "when the caller is an LLM/tool-use agent and wants the agent-gated checks; " +
        "operators can default every call to agent mode with LINKLINT_AGENT_MODE=1.",
    },
  );
  registerTools(server, options.defaultAgentMode ?? false);
  return server;
}

/** Start the server over stdio (local-only; no outbound network, no telemetry). */
export async function main(): Promise<void> {
  const server = createServer({ defaultAgentMode: parseAgentModeEnv(process.env.LINKLINT_AGENT_MODE) });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Run when invoked directly (bin entrypoint).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("linklint-mcp failed to start:", err);
    process.exit(1);
  });
}
