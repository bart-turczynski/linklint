/**
 * Stable, versioned result contract returned by every linklint channel.
 *
 * See docs/PRD.md §5.3 (FR-SCORE-*) and docs/architecture.md §6.
 * The shape is identical for the library and the MCP server.
 *
 * This module is a re-export barrel: the contract is split across focused
 * files, kept here so existing named imports resolve identically.
 */

export * from "./base.js";
export * from "./parsed.js";
export * from "./result.js";
export * from "./options.js";
export * from "./enrich.js";
