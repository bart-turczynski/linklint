/**
 * TLDs that are also common file extensions. A registrable domain on one of
 * these (`invoice.zip`, `setup.mov`) can masquerade as a downloadable file, so
 * the string makes a false claim about its own type — architecture §1.1 form 3.
 * Owned by the `file_extension_tld` detector.
 *
 * This module previously also carried `RISKY_TLDS`, the curated high-abuse set
 * behind `risky_tld`. That detector was deleted in schema `1.10` /
 * weights `1.19` (`LINK-brsntven`, architecture §6.1.5): membership of a
 * curated TLD list is a fact about the world, and a watchlist may NAME a
 * structural anomaly but never CREATE one. The version stamp stayed — it is the
 * only pin covering the table below — and was renamed
 * `dataVersions.riskyTlds` → `dataVersions.fileExtensionTlds` to say what it
 * now pins.
 *
 * Version-pinned via `dataVersions.fileExtensionTlds`. Entries are the
 * effective TLD (last label).
 */
export const FILE_EXTENSION_TLDS: ReadonlySet<string> = new Set(["zip", "mov"]);

export function isFileExtensionTld(tld: string): boolean {
  return FILE_EXTENSION_TLDS.has(tld.toLowerCase());
}
