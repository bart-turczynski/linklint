/**
 * Seed list of frequently-impersonated brand keywords (J7). Used by the
 * `brand_in_path` detector to spot a brand reference planted in the PATH of an
 * unrelated host (`evil.com/paypal.com/login`).
 *
 * This is a SEED set, intentionally small and high-confidence (household-name
 * phishing targets). Epic G owns the authoritative, expandable brand list and
 * the brand-aware scoring escalations (host-side edit-distance, IDNA/homoglyph
 * brand matches). When that lands, this set folds into it; the detector reads
 * from whatever the canonical accessor exposes.
 *
 * Entries are lowercase brand keywords (no TLD), matched against path segments
 * either bare (`/paypal/login`) or domain-shaped (`/paypal.com/`).
 */
export const BRAND_KEYWORDS: ReadonlySet<string> = new Set([
  // payments / finance
  "paypal",
  "stripe",
  "venmo",
  "coinbase",
  "binance",
  "chase",
  "wellsfargo",
  "citibank",
  "barclays",
  "revolut",
  // big tech / platforms
  "google",
  "gmail",
  "apple",
  "icloud",
  "microsoft",
  "outlook",
  "office365",
  "amazon",
  "facebook",
  "instagram",
  "whatsapp",
  "netflix",
  "linkedin",
  "dropbox",
  "adobe",
  "docusign",
  "steam",
  "spotify",
  // commerce / logistics
  "ebay",
  "walmart",
  "dhl",
  "fedex",
  "ups",
  "usps",
]);

export function isBrandKeyword(token: string): boolean {
  return BRAND_KEYWORDS.has(token.toLowerCase());
}
