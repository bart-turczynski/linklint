/**
 * linklint/experimental — curated secondary entry point (LINK-kflglaxa).
 *
 * Advanced internals for power consumers: the detector registry + individual
 * detectors, structural scan functions, the policy channel, and the
 * parser/unicode helpers. These are NOT covered by the stable semver contract —
 * names and shapes here may change between minor releases. Re-exported from the
 * same internal modules the root index uses. Named detector exports come from
 * the detector registry so new checks cannot silently appear only through
 * DETECTORS without a matching named export.
 */

export * from "./detectors/registry.js";
export {
  classifyHost,
  type IpClassification,
} from "./detectors/ip-classification.js";
export { scanAmbiguousAuthority } from "./detectors/ambiguous-authority.js";
export { scanSeparatorLookalike } from "./detectors/separator-lookalike.js";
export { scanIdnaMappingAmbiguity } from "./detectors/idna-mapping-ambiguity.js";
export { scanControlChar } from "./detectors/control-char.js";
export type { Detector, DetectorFinding, InspectionContext } from "./detectors/types.js";
export { runPolicy, policyConfigured } from "./policy/policy.js";
export { parse } from "./parse/parse.js";
// URL relationship comparison — same origin / same site (LINK-vycgfumd).
// A SECOND question from `inspect()`'s, and the one production consumer of the
// PSL's PRIVATE-inclusive view (architecture §6.1).
export {
  compareUrls,
  type ComparedUrl,
  type OriginKind,
  type UrlComparison,
  type UrlRelation,
} from "./compare/compare-urls.js";

export { findConfusables } from "./unicode/confusables.js";
export { skeleton } from "./unicode/skeleton.js";
