import type { Detector, DetectorFinding } from "./types.js";
import { foldAsciiDigitHomoglyphs } from "../data/ascii-confusables.js";
import {
  BRAND_DOMAIN_SET,
  BRAND_LABEL_SET,
  asciiRegistrableBrandCandidate,
} from "./brand-utils.js";

/**
 * Brand-proximity detection, emitting a SINGLE code:
 *
 *   - `brand_homoglyph` (HIGH confidence) — some unit of the host folds, via
 *     ASCII digit look-alikes (`0`→o, `1`→l, `5`→s), to EXACTLY a watchlist brand.
 *     `paypa1.com` → `paypal.com`, `g00gle.com` → `google.com`. Because the folded
 *     skeleton matches a real brand byte-for-byte, this is the highest-precision
 *     brand-impersonation signal we have.
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
 * ── What is compared: two tiers, one code (LINK-lippdgpn) ─────────────────
 * TIER 1 — the FULL registrable domain string (label + public suffix) against
 * `BRAND_DOMAIN_SET`, so the fold must land on a real brand domain including
 * its suffix. `paypa1.com` → `paypal.com`.
 *
 * TIER 2 — the HYPHEN TOKEN as the unit of analysis. Every host label is split
 * on `-` and each token is joined against `BRAND_LABEL_SET` (the brands'
 * significant labels) under the SAME structural fold gate. This is what makes
 * `paypa1-login.com`, `sp0tify-app.com`, `paypa1.vercel.app` and
 * `turb0tax.intuit.com` visible: tier 1 folds the registrable domain as ONE
 * unit, so a hyphen or a shared hosting suffix hid the fold entirely.
 *
 * The fold gate is the whole safety argument for tier 2. It fires ONLY when
 * `fold(token) !== token && BRAND_LABEL_SET.has(fold(token))`, so EXACT label
 * matching stays dead and the deleted `brand_combosquat`'s false positives
 * cannot return: `secure-paypal-login.com` has no fold and stays silent.
 * Evidence for fold-gated label matching (LINK-pblqdrco): 0 false positives
 * across 36,200 unseen GitHub logins; a 576-probe live study returned 25 hits,
 * all impersonation or takedowns, zero legitimate businesses.
 *
 * The two tiers are DEDUPED by construction — tier 1 returns immediately, so
 * `paypa1.com` (which matches at both tiers) still emits exactly one
 * `brand_homoglyph` reason and is unchanged at 0.60/high.
 *
 * NOT in scope here: hyphen tokenization of `ascii_homoglyph`'s list-free 0.20
 * floor. That variant has no corpus evidence and belongs to `LINK-aqdajqfi`.
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

export const brandHomoglyph: Detector = {
  id: "brand_homoglyph",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.isIp) return [];

    // ── Tier 1: the registrable domain as one unit ──────────────────────────
    // Pure-ASCII, non-IP registrable domain that is not itself a brand. The real
    // brand never fires — it IS the brand; non-ASCII (IDN) hosts belong to the
    // confusable / IDNA detectors.
    const raw = asciiRegistrableBrandCandidate(ctx);
    if (raw !== null) {
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
    }

    // ── Tier 2: the hyphen token as the unit of analysis ────────────────────
    // Returning above means a domain-tier hit never reaches here, so a host that
    // matches at BOTH tiers (paypa1.com) still yields exactly one reason.
    for (const rawLabel of ctx.hostLabels) {
      const label = rawLabel.toLowerCase();
      // Punycode labels are the confusable / IDNA detectors' territory, and their
      // ACE prefix is itself hyphenated — never tokenize one.
      if (label.startsWith("xn--")) continue;
      for (const token of label.split("-")) {
        // Pure-ASCII alphanumeric tokens only: anything else is not a word with
        // digits standing in for letters.
        if (!/^[a-z0-9]+$/.test(token)) continue;
        const tokenSkel = foldAsciiDigitHomoglyphs(token);
        // THE FOLD GATE. No fold, no fire — exact-label matching stays dead.
        if (tokenSkel === token) continue;
        if (!/^[a-z]+$/.test(tokenSkel)) continue;
        if (!BRAND_LABEL_SET.has(tokenSkel)) continue;
        return [
          {
            code: "brand_homoglyph",
            detail:
              `host token '${token}' folds to the known brand label '${tokenSkel}' via ` +
              "ASCII digit look-alikes (0->o, 1->l, 5->s)",
          },
        ];
      }
    }

    return [];
  },
};
