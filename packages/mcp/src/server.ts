#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools/index.js";

/** Package version, kept in sync with package.json. */
export const SERVER_VERSION = "0.1.0-dev.0";

/**
 * Create a fully-configured linklint MCP server (tools registered, no transport
 * attached). Exported so tests can connect it to an in-memory transport.
 */
export function createServer(): McpServer {
  const server = new McpServer(
    { name: "linklint", version: SERVER_VERSION },
    {
      instructions:
        "linklint inspects URLs for deception offline. Call check_url (or " +
        "check_domain) on any untrusted URL BEFORE fetching it, and avoid " +
        "fetching results with severity high or critical.",
    },
  );
  registerTools(server);
  return server;
}

/** Start the server over stdio (local-only; no outbound network, no telemetry). */
export async function main(): Promise<void> {
  const server = createServer();
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
