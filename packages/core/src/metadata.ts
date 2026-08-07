/**
 * linklint/metadata — curated secondary entry point (LINK-kflglaxa).
 *
 * Stable, semver-tracked metadata for docs/UI surfaces: the reason-code
 * registry helpers, the scoring weights table, and the data-version stamps.
 * Re-exports from the same internal modules the root index uses; depend on this
 * subpath instead of reaching into `src/`.
 */

export { reasonMeta, weightFor, type ReasonCodeMeta } from "./schema/reason-codes.js";
export { WEIGHTS, WEIGHTS_VERSION } from "./scoring/weights.js";
export { DATA_VERSIONS } from "./data/versions.js";
export {
  PSL_PROVENANCE,
  pslOutdated,
  type PslProvenance,
  type PslDateKind,
  type PslStaleness,
  type PslSnapshot,
} from "./data/psl-provenance.js";
