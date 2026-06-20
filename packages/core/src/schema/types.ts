/**
 * Stable, versioned result contract returned by every linklint channel.
 *
 * See docs/PRD.md §5.3 (FR-SCORE-*) and docs/architecture.md §6.
 * The shape is identical for the library and the MCP server.
 */

/** Current schema version. Bumped only on a breaking change to this contract. */
export const SCHEMA_VERSION = "1.0" as const;

/** Conceptual inspection layers. v1 implements `lexical` only. */
export type Layer = "lexical" | "resolution" | "reputation";

/** Top-level disposition of an inspection. */
export type Status = "ok" | "invalid";

/**
 * Severity bands derived from `score` (FR-SCORE-1b). `null` only on invalid
 * input, where no score could be computed.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Parsed URL components surfaced on an `ok` result. `null` on invalid input. */
export interface ParsedUrl {
  /** Lower-cased scheme without the trailing colon, or `null` if none present. */
  scheme: string | null;
  /** The userinfo (`user:pass`) segment before `@`, or `null`. */
  userinfo: string | null;
  /** The host as it appears in the authority (U-label form where applicable). */
  effectiveHost: string | null;
  /** Registrable domain (eTLD+1) per the Public Suffix List, or `null`. */
  registrableDomain: string | null;
  /** Public suffix (eTLD) per the PSL, or `null`. */
  publicSuffix: string | null;
  /** Subdomain labels left of the registrable domain (may be empty string). */
  subdomain: string | null;
  /** Host split into labels, left-to-right. Empty for IP / hostless inputs. */
  hostLabels: string[];
  /** Numeric port, or `null` when not explicitly present. */
  port: number | null;
  /** Path component (may be empty string). */
  path: string;
  /** Query string without the leading `?`, or `null`. */
  query: string | null;
  /** Fragment without the leading `#`, or `null`. */
  fragment: string | null;
  /** True when the effective host is an IP literal (v4 or v6). */
  isIp: boolean;
}

/**
 * A single named finding. `weight` is the score contribution attached by the
 * core from the version-pinned weights table — detectors never supply it.
 * Informational reasons carry `weight: 0`.
 */
export interface Reason {
  code: string;
  layer: Layer;
  detail: string;
  weight: number;
}

/** Which URL component a confusable character was found in. */
export type ConfusableComponent = "host" | "path" | "query";

/**
 * Per-character confusable finding. A structured expansion of the
 * `confusable_char` / `confusable_in_path` reasons (FR-SCORE-2a).
 */
export interface Confusable {
  /** The offending character as it appears in the input. */
  char: string;
  /** Its codepoint, e.g. `"U+0430"`. */
  codepoint: string;
  /** Human-readable description of what it is confusable with, e.g. `"a (U+0061)"`. */
  confusableWith: string;
  /** Which component it was found in. */
  component: ConfusableComponent;
  /** Zero-based index of the character within that component. */
  position: number;
}

/** Version stamps for every reproducibility-relevant data/algorithm source. */
export interface DataVersions {
  publicSuffixList: string;
  unicodeConfusables: string;
  unicodeScripts: string;
  idna: string;
  riskyTlds: string;
  brands: string;
  weights: string;
}

/** Options accepted by `inspect()`. Reserved for v1; no behavior toggles yet. */
export interface InspectOptions {
  /**
   * Maximum number of recursive percent-decode passes. Bounded to keep
   * inspection total over adversarial input (no decode-bomb). Defaults to a
   * safe internal value.
   */
  maxDecodeDepth?: number;
}

/** The full inspection result. */
export interface InspectResult {
  schemaVersion: typeof SCHEMA_VERSION;
  status: Status;
  input: string;
  parsed: ParsedUrl | null;
  /** Risk score in [0,1], or `null` on invalid input. */
  score: number | null;
  severity: Severity | null;
  reasons: Reason[];
  confusables: Confusable[];
  checksRun: string[];
  checksSkipped: string[];
  dataVersions: DataVersions;
}
