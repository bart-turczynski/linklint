/**
 * linklint core — explainable, offline-first URL inspection.
 *
 * Public API: a single synchronous `inspect()` entry point, the result schema
 * types, the reason-code registry + weights (for docs/UI surfaces), and the
 * individual detectors (for advanced consumers).
 */

export { inspect } from "./inspect.js";

// Schema / result contract
export {
  SCHEMA_VERSION,
  type InspectResult,
  type InspectOptions,
  type ParsedUrl,
  type Reason,
  type Confusable,
  type ConfusableComponent,
  type DataVersions,
  type Layer,
  type Status,
  type Severity,
} from "./schema/types.js";

// Reason-code registry + scoring reference data
export {
  REASON_CODES,
  reasonMeta,
  weightFor,
  type ReasonCode,
  type ReasonCodeMeta,
} from "./schema/reason-codes.js";
export { WEIGHTS, WEIGHTS_VERSION, severityForScore } from "./scoring/weights.js";

// Data versions
export { DATA_VERSIONS } from "./data/versions.js";

// Detector internals (advanced consumers)
export {
  DETECTORS,
  normalizationDelta,
  confusableChar,
  mixedScript,
  invisibleChar,
  bidiOverride,
  userinfoPresent,
  ipObfuscation,
  embeddedDomain,
  riskyTld,
  fileExtensionTld,
  encodingObfuscation,
  dangerousScheme,
  confusableInPath,
} from "./detectors/registry.js";
export { scanAmbiguousAuthority } from "./detectors/ambiguous-authority.js";
export { scanSeparatorLookalike } from "./detectors/separator-lookalike.js";
export { scanIdnaMappingAmbiguity } from "./detectors/idna-mapping-ambiguity.js";
export { scanControlChar } from "./detectors/control-char.js";
export type { Detector, DetectorFinding, InspectionContext } from "./detectors/types.js";

// Parsing / reference-data helpers (advanced consumers)
export { parse } from "./parse/parse.js";
export { findConfusables } from "./unicode/confusables.js";
export { RISKY_TLDS, FILE_EXTENSION_TLDS } from "./data/risky-tlds.js";
