/**
 * @linklint/mcp — a thin, local-only MCP adapter over the linklint core.
 * Exposes `check_url` and `check_domain` (alias) returning the exact core schema.
 */
export { createServer, main, SERVER_VERSION } from "./server.js";
export { registerTools } from "./tools/index.js";
export { runCheck, toToolResult, PREFETCH_GUIDANCE } from "./tools/check.js";
