/**
 * ASCII letter-shaped digit confusables (shared). The single
 * source of truth for the three digits that read unambiguously as a Latin
 * letter when embedded in an otherwise-alphabetic word:
 *   `0`→o, `1`→l, `5`→s   (g00gle → google, paypa1 → paypal, mas5 → mass)
 *
 * These three — and ONLY these three — are mapped on purpose. The digits
 * `2 3 4 6 7 8 9` are NOT letter-shapes in any common ASCII font, so they are
 * left untouched: this is what keeps `s3`, `bet365`, `route53`, `web3`, `i18n`,
 * `blink182` from ever folding to a brand or word. Fold only what is visually a
 * letter; treat every other digit as a genuine number.
 *
 * Consumers:
 *   - `ascii_homoglyph` (detectors/ascii-homoglyph.ts) — the general,
 *     brand-free structural signal, which folds a label to its readable skeleton.
 *   - `brand_lookalike` (detectors/brand-lookalike.ts) — folds the
 *     registrable domain and tests the skeleton for an exact brand match.
 *
 * No `dataVersions` pin: this is a static, intrinsic property of the ASCII
 * glyph repertoire (which digits look like which letters), not external/curated
 * data like the brand watchlist or risky-TLD list that evolves over time. Plain
 * tree-shakeable module exports under src/data/, matching risky-tlds.ts /
 * brands.ts conventions.
 */

/** Letter-shaped ASCII digits and the lowercase letter each one resembles. */
export const ASCII_DIGIT_HOMOGLYPHS: Readonly<Record<string, string>> = {
  "0": "o",
  "1": "l",
  "5": "s",
};

/**
 * Replace every letter-shaped digit (`0 1 5`) in `s` with the letter it
 * resembles, leaving all other characters — including the unmapped digits
 * `2 3 4 6 7 8 9` — untouched. Pure; case is preserved for non-digit chars.
 *
 *   foldAsciiDigitHomoglyphs("g00gle")  === "google"
 *   foldAsciiDigitHomoglyphs("paypa1")  === "paypal"
 *   foldAsciiDigitHomoglyphs("bet365")  === "bet36s"   // 6,3 untouched; 5→s
 *   foldAsciiDigitHomoglyphs("route53") === "routes3"  // 5→s; 3 untouched
 */
export function foldAsciiDigitHomoglyphs(s: string): string {
  let out = "";
  for (const ch of s) {
    out += ASCII_DIGIT_HOMOGLYPHS[ch] ?? ch;
  }
  return out;
}
