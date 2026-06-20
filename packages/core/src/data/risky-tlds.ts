/**
 * Curated risky-TLD list (FR-D-9). Persistently high-abuse / free-registration
 * TLDs — a low-weight, contextual signal only (never flags on its own).
 *
 * The extension-confusable TLDs that collide with common file extensions
 * (`.zip`, `.mov`) are owned by the sharper, higher-weight `file_extension_tld`
 * detector (Epic J / J6) — kept out of this set so the two never double-count.
 *
 * Version-pinned via dataVersions.riskyTlds. Entries are the effective TLD
 * (last label).
 */
export const RISKY_TLDS: ReadonlySet<string> = new Set([
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

/**
 * TLDs that are also common file extensions (J6). A registrable domain on one of
 * these (`invoice.zip`, `setup.mov`) can masquerade as a downloadable file. These
 * are owned by `file_extension_tld`, NOT `risky_tld`, so the two never overlap.
 */
export const FILE_EXTENSION_TLDS: ReadonlySet<string> = new Set(["zip", "mov"]);

export function isFileExtensionTld(tld: string): boolean {
  return FILE_EXTENSION_TLDS.has(tld.toLowerCase());
}
