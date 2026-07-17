/**
 * linklint core — explainable, offline-first URL inspection.
 *
 * Stable API: a single synchronous `inspect()` entry point, the result schema
 * types, and metadata useful to docs/UI surfaces.
 *
 * Compatibility API: the root still re-exports advanced detector, policy,
 * parsing, and reference-data helpers for pre-subpath consumers. New advanced
 * consumers should prefer `linklint/experimental` or `linklint/data`; root
 * compatibility may narrow after a documented deprecation window.
 */

export { inspect } from "./inspect.js";

// Async enrichment framework (opt-in; roadmap resolution/reputation layers).
// `inspectAsync` runs the sync `inspect()` first, then caller-supplied enrichers.
export { inspectAsync, type InspectAsyncOptions } from "./inspect-async.js";

// Opt-in result cache for async enrichers (per-source TTLs; roadmap L2/L3).
// The interface is a type; the in-memory default is a runtime class.
export { InMemoryEnrichmentCache, type EnrichmentCache } from "./enrichment-cache.js";

// Opt-in per-source governor for async enrichers: bounded timeout + token-bucket
// rate limit + exponential backoff (roadmap L2/L3). The interface + decision +
// config are types; the in-memory default is a runtime class.
export {
  InMemoryEnrichmentGovernor,
  type EnrichmentGovernor,
  type EnrichmentGovernorConfig,
  type GovernorDecision,
} from "./enrichment-governor.js";

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
  type Enricher,
  type EnricherFinding,
  type EnrichmentContext,
  type EnrichmentLayer,
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

// Detector internals (legacy/advanced compatibility)
export * from "./detectors/registry.js";
export { scanAmbiguousAuthority } from "./detectors/ambiguous-authority.js";
export { scanSeparatorLookalike } from "./detectors/separator-lookalike.js";
export { scanIdnaMappingAmbiguity } from "./detectors/idna-mapping-ambiguity.js";
export { scanControlChar } from "./detectors/control-char.js";
export type { Detector, DetectorFinding, InspectionContext } from "./detectors/types.js";

// Policy channel (advanced consumers)
export { runPolicy, policyConfigured } from "./policy/policy.js";

// Parsing / reference-data helpers (advanced consumers)
export { parse } from "./parse/parse.js";
export { findConfusables } from "./unicode/confusables.js";
export { skeleton } from "./unicode/skeleton.js";
export { RISKY_TLDS, FILE_EXTENSION_TLDS } from "./data/risky-tlds.js";
export { BRAND_DOMAINS, BRAND_WATCHLIST, type BrandEntry } from "./data/brands.js";
