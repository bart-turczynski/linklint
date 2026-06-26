import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CHECK_DOMAIN_INPUT,
  CHECK_URL_INPUT,
  PREFETCH_GUIDANCE,
  resolveAgentMode,
  runCheck,
  toToolResult,
} from "./check.js";

/**
 * Register the linklint tools on an MCP server. Shared by the stdio entrypoint
 * and the in-memory test harness so both exercise the exact same surface.
 *
 * Both tools are read-only, do no outbound network I/O, and emit no telemetry
 * (FR-MCP-2). `check_domain` is an alias of `check_url` for hostname-oriented
 * callers — both return the identical core schema (no channel drift).
 *
 * `defaultAgentMode` is the server-level fallback (set from LINKLINT_AGENT_MODE
 * at the stdio entrypoint). A per-call `agentMode` always overrides it; only an
 * omitted value uses the default. The resolved flag is passed through to core
 * inspect() explicitly.
 */
export function registerTools(server: McpServer, defaultAgentMode = false): void {
  server.registerTool(
    "check_url",
    {
      title: "Check a URL before fetching",
      description: PREFETCH_GUIDANCE,
      inputSchema: CHECK_URL_INPUT,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ url, agentMode }) =>
      toToolResult(runCheck(url, resolveAgentMode(agentMode, defaultAgentMode) ? { agentMode: true } : {})),
  );

  server.registerTool(
    "check_domain",
    {
      title: "Check a domain/hostname before fetching",
      description: `${PREFETCH_GUIDANCE} Alias of check_url for hostname-oriented callers.`,
      inputSchema: CHECK_DOMAIN_INPUT,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ domain, agentMode }) =>
      toToolResult(runCheck(domain, resolveAgentMode(agentMode, defaultAgentMode) ? { agentMode: true } : {})),
  );
}
