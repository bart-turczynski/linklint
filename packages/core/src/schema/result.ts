import { SCHEMA_VERSION, type Layer, type Status, type Severity } from "./base.js";
import type { ParsedUrl } from "./parsed.js";
import type { PslSnapshot } from "../data/psl-provenance.js";
import type { EnrichmentReport } from "./enrich.js";

export type { PslSnapshot } from "../data/psl-provenance.js";

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
  /**
   * Caller escape hatch (see {@link import("./options.js").InspectOptions.suppressReasons}).
   * Present and `true` only when a caller-supplied suppression rule marked this
   * reason a false positive: the reason STAYS in `reasons[]` (never silently
   * deleted) but its `weight` is zeroed so it contributes nothing to `score`.
   * Absent by default — with no `suppressReasons` option the field never appears,
   * so default output is byte-for-byte unchanged.
   */
  suppressed?: boolean;
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
  /**
   * Curated cloud metadata / provider-internal endpoint table. Vendor-documented, NOT
   * IANA-derived (IANA registers ranges, not which address inside them a cloud
   * answers metadata on), so it carries its own stamp independent of any
   * registry pin.
   */
  cloudMetadata: string;
  /**
   * IANA IPv4/IPv6 Special-Purpose Address Registry snapshot the literal-IP
   * range buckets are generated from (`data/ip-ranges.generated.ts`). Separate
   * from {@link cloudMetadata}: that table is vendor-documented, this one is the
   * registry itself.
   */
  ipRanges: string;
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
  /**
   * Confidence in [0,1] that the contributing signals are reliable (FR-SCORE-2b).
   * Independent of `score`/`weight`: `weight` encodes a signal's scoring
   * reliability, `confidence` is a separate advisory measure. Deterministic
   * lexical results (everything sync `inspect()` produces, including
   * `status: "invalid"`) are fully deterministic at `1.0`. Probabilistic
   * (resolution/reputation) enrichers may lower it; the result's value is the
   * MINIMUM over all contributing signals (see {@link import("../inspect-async.js").inspectAsync}).
   */
  confidence: number;
  reasons: Reason[];
  confusables: Confusable[];
  checksRun: string[];
  checksSkipped: string[];
  dataVersions: DataVersions;
  /**
   * Provenance of the Public Suffix List snapshot this verdict's registrable-
   * domain reasoning rests on: the snapshot `date` (deterministic) and a `stale`
   * advisory flag against the default 180-day freshness window (time-relative;
   * see {@link PslSnapshot}). Added in schema 1.2 (LINK-rkhuihjx). Consumers
   * learn the provenance of the trust boundary they are handed.
   */
  pslSnapshot: PslSnapshot;
  /**
   * Versioned per-source online outcomes and evidence. Present only when
   * `inspectAsync()` is called with at least one enricher; synchronous
   * `inspect()` output and the no-enricher async path do not add the field.
   * Added in schema 1.3 (LINK-isytbvjy).
   */
  enrichment?: EnrichmentReport;
}
