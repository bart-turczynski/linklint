import type { Detector, DetectorFinding } from "./types.js";
import { BRAND_DOMAINS } from "../data/brands.js";
import { foldAsciiDigitHomoglyphs } from "../data/ascii-confusables.js";

/**
 * G2 — brand-proximity detection (Epic G). A SINGLE detector emitting TWO codes,
 * in priority order (it reports the strongest single finding per input):
 *
 *   - `brand_homoglyph` (HIGH confidence) — the registrable domain folds, via
 *     ASCII digit look-alikes (`0`→o, `1`→l, `5`→s), to EXACTLY a watchlist brand
 *     domain. `paypa1.com` → `paypal.com`, `g00gle.com` → `google.com`. Because
 *     the folded skeleton matches a real brand byte-for-byte, this is the highest-
 *     precision brand-impersonation signal we have.
 *
 *   - `brand_lookalike` (lower confidence) — the registrable domain is a bounded,
 *     transposition-aware edit-distance near-miss of a watchlist brand domain:
 *     dnstwist's permutation logic run in reverse. `gogole.com`, `microsoftt.com`,
 *     `paypal.co` (TLD swap). Genuine typos / look-alikes that are not a clean
 *     digit fold.
 *
 * The two are mutually exclusive per input: a clean digit-fold to a real brand
 * fires `brand_homoglyph` and short-circuits; everything else falls through to
 * the fuzzy edit-distance path. We never double-report the same brand.
 *
 * ── What is compared ──────────────────────────────────────────────────────
 * The FULL registrable domain string (label + public suffix), NOT the bare
 * label. TLD-swap typosquats — `paypal.co` for `paypal.com` — are real, high-
 * value positives only visible when the suffix is part of the compared string.
 *
 * ── Precision (SC-2, precision=1 discipline) ───────────────────────────────
 * - Exact match to the real brand (distance 0 / skeleton == raw and on the list)
 *   never fires — it IS the brand.
 * - `brand_homoglyph` requires the folded skeleton to equal a real brand domain
 *   exactly, with at least one digit actually folded and an alphabetic result —
 *   so a degenerate mostly-digit string cannot fold into a brand. Exact-match to
 *   a real brand is itself the precision backstop.
 * - `brand_lookalike` gates on the matched brand's significant label length:
 *   distance 1 fires only when the brand label length ≥ 5; distance 2 only when
 *   ≥ 8 (longer brands only, where a 2-edit neighbour is overwhelmingly a
 *   deliberate look-alike). This contains `visa.com`↔`vista.com`,
 *   `ups.com`↔`usp.com`-class short-domain collisions.
 *
 * ── Non-ASCII registrable domains are out of scope ─────────────────────────
 * We only run on a PURE-ASCII registrable domain. An IDN / non-ASCII host
 * (`wordpreß.com`, `straße.de`) is the territory of the confusable / mixed-script
 * / `idna_mapping_ambiguity` detectors; measuring raw edit distance from its
 * Unicode form to an ASCII brand domain is meaningless and produces spurious hits
 * (it fixed a real `wordpreß.com` ≈ `wordpress.com` false positive). The brand
 * watchlist is all-ASCII, so a non-ASCII input could only ever be a false near-
 * miss here.
 *
 * ── Performance (<5ms) ──────────────────────────────────────────────────────
 * The OSA (optimal string alignment) Damerau-Levenshtein is bounded: it early-
 * exits the moment the best achievable distance for a row exceeds MAX_DISTANCE,
 * and a length-difference pre-check skips rows that cannot possibly be within
 * range. Against ~100 short domains this is well under budget. The skeleton-fold
 * path is a single string pass + set membership.
 */

const MAX_DISTANCE = 2;
/** Min brand-label length to allow a distance-1 `brand_lookalike` hit. */
const MIN_LABEL_FOR_DISTANCE_1 = 5;
/** Min brand-label length to allow a distance-2 `brand_lookalike` hit (stricter). */
const MIN_LABEL_FOR_DISTANCE_2 = 8;

/** Brand domains as a Set for O(1) exact-match membership. */
const BRAND_DOMAIN_SET: ReadonlySet<string> = new Set(BRAND_DOMAINS);

/**
 * Optimal String Alignment distance (Damerau-Levenshtein with adjacent
 * transpositions), bounded by `max`. Returns a value > `max` (specifically
 * `max + 1`) as soon as every cell in a row exceeds `max`, so callers can treat
 * any return value > `max` as "too far".
 */
function boundedOsaDistance(a: string, b: string, max: number): number {
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > max) return max + 1;
  if (la === 0) return lb;
  if (lb === 0) return la;

  let prevPrev = new Array<number>(lb + 1).fill(0);
  let prev = new Array<number>(lb + 1);
  let curr = new Array<number>(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;

  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(
        prev[j]! + 1, // deletion
        curr[j - 1]! + 1, // insertion
        prev[j - 1]! + cost, // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prevPrev[j - 2]! + 1); // transposition
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    // Early exit: no future row can drop below the current row minimum.
    if (rowMin > max) return max + 1;
    const tmp = prevPrev;
    prevPrev = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[lb]!;
}

/** The brand's significant (registrable) label, left of the public suffix. */
function significantLabelLength(brandDomain: string): number {
  const dot = brandDomain.indexOf(".");
  return dot === -1 ? brandDomain.length : dot;
}

export const brandLookalike: Detector = {
  id: "brand_lookalike",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const input = ctx.registrableDomain;
    if (!input || ctx.isIp) return [];
    // Pure-ASCII only: non-ASCII (IDN) hosts belong to the confusable / IDNA
    // detectors, and the all-ASCII brand watchlist cannot be a genuine near-miss
    // of a Unicode domain.
    if (!/^[\x00-\x7f]+$/.test(input)) return [];

    const raw = input.toLowerCase();

    // (1) The real brand itself: never fire — it IS the brand.
    if (BRAND_DOMAIN_SET.has(raw)) return [];

    // (2) brand_homoglyph — fold ASCII digit look-alikes; if the skeleton is
    // EXACTLY a watchlist brand, that is the highest-confidence impersonation.
    const skel = foldAsciiDigitHomoglyphs(raw);
    if (skel !== raw && BRAND_DOMAIN_SET.has(skel)) {
      // Sanity guard (J4's spirit): a digit was actually folded and the result is
      // alphabetic (plus dots/suffix) — a degenerate mostly-digit string can't
      // pass, and the exact-match-to-a-real-brand above is the precision backstop.
      if (/[a-z]/.test(skel) && /^[a-z.]+$/.test(skel)) {
        return [
          {
            code: "brand_homoglyph",
            detail:
              `registrable domain '${raw}' folds to the known brand '${skel}' via ` +
              "ASCII digit look-alikes (0->o, 1->l, 5->s)",
          },
        ];
      }
    }

    // (3) brand_lookalike — bounded edit-distance near-miss of a brand domain.
    let best: { brand: string; distance: number } | null = null;
    for (const brand of BRAND_DOMAINS) {
      const distance = boundedOsaDistance(raw, brand, MAX_DISTANCE);
      // Distance 0 = a real brand we somehow didn't catch above; never fire.
      if (distance === 0) return [];
      if (distance > MAX_DISTANCE) continue;

      const labelLen = significantLabelLength(brand);
      const minLabel =
        distance === 1 ? MIN_LABEL_FOR_DISTANCE_1 : MIN_LABEL_FOR_DISTANCE_2;
      if (labelLen < minLabel) continue;

      if (best === null || distance < best.distance) {
        best = { brand, distance };
      }
    }

    if (best === null) return [];
    return [
      {
        code: "brand_lookalike",
        detail:
          `registrable domain '${raw}' is edit-distance ${best.distance} from ` +
          `the known brand '${best.brand}'`,
      },
    ];
  },
};
