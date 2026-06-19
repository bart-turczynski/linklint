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
export { DETECTORS } from "./detectors/registry.js";
export type { Detector, DetectorFinding, InspectionContext } from "./detectors/types.js";
