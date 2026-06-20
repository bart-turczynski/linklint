/**
 * linklint/experimental — curated secondary entry point (LINK-kflglaxa).
 *
 * Advanced internals for power consumers: the detector registry + individual
 * detectors, structural scan functions, the policy channel, and the
 * parser/unicode helpers. These are NOT covered by the stable semver contract —
 * names and shapes here may change between minor releases. Re-exported from the
 * same internal modules the root index uses.
 */

export {
  DETECTORS,
  normalizationDelta,
  confusableChar,
  mixedScript,
  asciiHomoglyph,
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
  brandInPath,
  brandLookalike,
  skeletonCollision,
  combosquatting,
  soundsquatting,
  bitsquatting,
  baitTokens,
  openRedirectParam,
  suspiciousExtension,
  punycodeMalformed,
  excessiveSubdomainDepth,
} from "./detectors/registry.js";
export { scanAmbiguousAuthority } from "./detectors/ambiguous-authority.js";
export { scanSeparatorLookalike } from "./detectors/separator-lookalike.js";
export { scanIdnaMappingAmbiguity } from "./detectors/idna-mapping-ambiguity.js";
export { scanControlChar } from "./detectors/control-char.js";
export type { Detector, DetectorFinding, InspectionContext } from "./detectors/types.js";
export { runPolicy, policyConfigured } from "./policy/policy.js";
export { parse } from "./parse/parse.js";
export { findConfusables } from "./unicode/confusables.js";
export { skeleton } from "./unicode/skeleton.js";
