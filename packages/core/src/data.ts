/**
 * linklint/data — curated secondary entry point (LINK-kflglaxa).
 *
 * Reference data lists used by detectors: the risky-TLD sets and the brand
 * watchlist. Re-exported from the same internal modules the root index uses so
 * consumers can read the reference data without deep-importing `src/`.
 */

export { RISKY_TLDS, FILE_EXTENSION_TLDS } from "./data/risky-tlds.js";
export { BRAND_DOMAINS, BRAND_WATCHLIST, type BrandEntry } from "./data/brands.js";
