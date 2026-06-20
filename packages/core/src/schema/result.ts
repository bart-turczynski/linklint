import { SCHEMA_VERSION, type Layer, type Status, type Severity } from "./base.js";
import type { ParsedUrl } from "./parsed.js";

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
