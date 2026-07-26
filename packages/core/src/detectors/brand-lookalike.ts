import type { Detector, DetectorFinding } from "./types.js";
import { foldAsciiDigitHomoglyphs } from "../data/ascii-confusables.js";
import { BRAND_DOMAIN_SET, asciiRegistrableBrandCandidate } from "./brand-utils.js";

/**
 * Brand-proximity detection, emitting a SINGLE code:
 *
 *   - `brand_homoglyph` (HIGH confidence) — the registrable domain folds, via
 *     ASCII digit look-alikes (`0`→o, `1`→l, `5`→s), to EXACTLY a watchlist brand
 *     domain. `paypa1.com` → `paypal.com`, `g00gle.com` → `google.com`. Because
 *     the folded skeleton matches a real brand byte-for-byte, this is the highest-
 *     precision brand-impersonation signal we have.
 *
 * ── Why only the fold path survives (LINK-cphogucn) ────────────────────────
 * linklint defends ONE claim: if `normalize(input) !== input`, something may be
 * hiding — and the brand watchlist is consulted only to NAME a structural
 * anomaly that was already detected independently. It may never CREATE a
 * finding. `brand_homoglyph` satisfies that rule: it fires only when
 * `skel !== raw`, i.e. a digit demonstrably folded to a letter.
 *
 * The former `brand_lookalike` (bounded OSA edit distance to a brand domain)
 * did not. `paypai.com` is structurally flawless — pure ASCII, single script,
 * no digits, no fold — and is suspicious only relative to knowing that
 * `paypal` exists and is worth money. That is claim (b) ("we detect
 * impersonation of high-value brands"), which this tool explicitly rejects, so
 * the step was deleted outright — the same disposition `brand_in_path` and
 * `brand_combosquat` got in LINK-blgvypxk.
 *
 * ── What is compared ──────────────────────────────────────────────────────
 * The FULL registrable domain string (label + public suffix), NOT the bare
 * label, so the fold must land on a real brand domain including its suffix.
 *
 * ── Precision (SC-2, precision=1 discipline) ───────────────────────────────
 * - Exact match to the real brand (skeleton == raw and on the list) never
 *   fires — it IS the brand.
 * - The fold must actually change the string, and the result must be
 *   alphabetic — so a degenerate mostly-digit string cannot fold into a brand.
 *
 * ── Non-ASCII registrable domains are out of scope ─────────────────────────
 * We only run on a PURE-ASCII registrable domain. An IDN / non-ASCII host
 * (`wordpreß.com`, `straße.de`) is the territory of the confusable / mixed-script
 * / `idna_mapping_ambiguity` detectors. The brand watchlist is all-ASCII, so a
 * non-ASCII input could never fold onto it anyway.
 *
 * ── Performance (<5ms) ──────────────────────────────────────────────────────
 * The skeleton-fold path is a single string pass + set membership.
 */

export const brandLookalike: Detector = {
  id: "brand_lookalike",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    // Pure-ASCII, non-IP registrable domain that is not itself a brand. The real
    // brand never fires — it IS the brand; non-ASCII (IDN) hosts belong to the
    // confusable / IDNA detectors.
    const raw = asciiRegistrableBrandCandidate(ctx);
    if (raw === null) return [];

    // brand_homoglyph — fold ASCII digit look-alikes; if the skeleton is
    // EXACTLY a watchlist brand, that is the highest-confidence impersonation.
    const skel = foldAsciiDigitHomoglyphs(raw);
    if (skel !== raw && BRAND_DOMAIN_SET.has(skel)) {
      // Sanity guard: a digit was actually folded and the result is
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

    return [];
  },
};
