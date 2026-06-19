import type { DataVersions } from "../schema/types.js";
import { WEIGHTS_VERSION } from "../scoring/weights.js";

/**
 * Version stamps for every reproducibility-relevant data/algorithm source used
 * by v1 (FR-SCORE-4a, NFR-DATA-1). Present on both `ok` and `invalid` results so
 * even parse failures are reproducible against a known parser/data release.
 *
 * Bump these deliberately when the underlying source is updated.
 */
export const DATA_VERSIONS: DataVersions = {
  // Public Suffix List ships inside tldts; we pin the tldts release.
  publicSuffixList: "tldts@7.4.3",
  // Curated high-risk confusables subset (OQ-1 / NFR-DATA-2).
  unicodeConfusables: "curated-v1",
  // Script detection uses the runtime's Unicode property data (\p{Script=...}).
  unicodeScripts: "ecma-unicode-property-escapes",
  // UTS-46 / IDNA normalization library.
  idna: "tr46@6.0.0",
  riskyTlds: "2026-06-19",
  weights: WEIGHTS_VERSION,
};
