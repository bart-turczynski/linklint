/**
 * Curated risky-TLD list (FR-D-9). Two kinds:
 *  - extension-confusable TLDs that collide with common file extensions
 *    (.zip, .mov) — a link can masquerade as a filename;
 *  - persistently high-abuse / free-registration TLDs.
 *
 * Low-weight, contextual signal only (never flags on its own). Version-pinned
 * via dataVersions.riskyTlds. Entries are the effective TLD (last label).
 */
export const RISKY_TLDS: ReadonlySet<string> = new Set([
  // extension-confusable
  "zip",
  "mov",
  // historically high-abuse / free registries
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "top",
  "xyz",
  "rest",
  "cam",
  "click",
  "country",
  "kim",
  "work",
  "loan",
  "men",
  "gdn",
]);

export function isRiskyTld(tld: string): boolean {
  return RISKY_TLDS.has(tld.toLowerCase());
}
