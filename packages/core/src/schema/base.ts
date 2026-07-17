/**
 * Stable, versioned result contract returned by every linklint channel.
 *
 * See docs/PRD.md §5.3 (FR-SCORE-*) and docs/architecture.md §6.
 * The shape is identical for the library and the MCP server.
 */

/**
 * Current schema version. Bumped on every contract change — additive minor
 * bumps included, so consumers can pin behavior: 1.0→1.1 added `confidence`,
 * 1.1→1.2 added `pslSnapshot` (both back-compatible field additions).
 */
export const SCHEMA_VERSION = "1.2" as const;

/**
 * Conceptual inspection layers. v1 implements `lexical` only.
 *
 * `policy` is a separate, caller-configured channel: policy reasons appear in
 * `reasons[]` but always carry `weight: 0`, so they annotate without moving the
 * deception score or severity (see {@link InspectOptions}).
 */
export type Layer = "lexical" | "resolution" | "reputation" | "policy";

/** Top-level disposition of an inspection. */
export type Status = "ok" | "invalid";

/**
 * Severity bands derived from `score` (FR-SCORE-1b). `null` only on invalid
 * input, where no score could be computed.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
