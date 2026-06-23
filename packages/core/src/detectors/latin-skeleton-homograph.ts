import type { Detector, DetectorFinding } from "./types.js";
import { skeleton } from "../unicode/skeleton.js";

/**
 * `homograph_latin_skeleton` (scoring, BLOCKER weight 1.0). The target-LESS
 * sibling of `homograph_skeleton_collision`: a non-ASCII registrable domain
 * whose UTS#39 confusable skeleton is *pure ASCII-Latin* — i.e. every character
 * is a Latin look-alike, so the whole host reads to a human as an ASCII word —
 * with NO brand list needed. An all-Cyrillic `сһаѕе.com` skeletonizes to
 * `chase.com`; `ехямрӏе.com` to `example.com`. Either way the host is Unicode
 * masquerading as Latin, which has no legitimate use, so it blocks.
 *
 * ── Why the "skeleton is pure ASCII" gate is precise (the FP investigation) ──
 * Empirically (and by construction of the UTS#39 confusables table, whose
 * targets are Latin/ASCII), a *legitimate* non-Latin word always contains at
 * least one character with no Latin confusable, so its skeleton retains a
 * non-ASCII codepoint and is NOT pure ASCII:
 *   пример → пpимep · россия → poccия · κόσμος → κóoμoς · 日本語 → 日本語
 * Only a label deliberately assembled ENTIRELY from Latin look-alikes folds to
 * pure ASCII. So `skeleton(host) ⊆ ASCII` cleanly separates the homograph
 * attack from genuine internationalized domains — no dictionary, no brand list.
 * (Residual: a short genuine word built only from the Latin-confusable subset,
 * e.g. Cyrillic `сор`→`cop`, still folds to ASCII — but such a host is visually
 * identical to its Latin reading and is exactly the "looks like ASCII" case the
 * block targets; a legitimate owner uses the IDN allow-list to override.)
 *
 * ── No double-fire with `idna_mapping_ambiguity` ────────────────────────────
 * A compatibility homograph (fullwidth Latin `ｇｏｏｇｌｅ.com`) NFKC-folds to pure
 * ASCII and is owned by `idna_mapping_ambiguity`. As in
 * `homograph_skeleton_collision`, we require the host to still carry a non-ASCII
 * codepoint AFTER NFKC, keeping this detector on the genuine cross-script case.
 *
 * ── Relationship to `homograph_skeleton_collision` ──────────────────────────
 * Every brand-collision input (skeleton == an ASCII brand) is also pure-ASCII,
 * so this fires on the brand case too; the two stack (this blocks, the collision
 * adds brand attribution). Additive by design — neither supersedes the other.
 *
 * Pure, synchronous, no network/fs — obeys every offline invariant.
 */

/** True when `s` contains any non-ASCII codepoint (i.e. is an IDN/Unicode host). */
function hasNonAscii(s: string): boolean {
  return !/^[\x00-\x7f]*$/.test(s);
}

export const latinSkeletonHomograph: Detector = {
  id: "homograph_latin_skeleton",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const input = ctx.registrableDomain;
    if (!input || ctx.isIp) return [];
    // Non-ASCII host only — a pure-ASCII host is not a cross-script homograph
    // (ASCII digit-folds like g00gle are owned by ascii_homoglyph/brand_homoglyph).
    if (!hasNonAscii(input)) return [];
    // Skip the compatibility-fold family (fullwidth/halfwidth Latin etc.): if the
    // host NFKC-folds to pure ASCII it is owned by idna_mapping_ambiguity.
    if (!hasNonAscii(input.normalize("NFKC"))) return [];

    const skel = skeleton(input.toLowerCase());
    // Fire only when the confusable skeleton is ENTIRELY ASCII — every character
    // folded to a Latin look-alike. A genuine non-Latin word retains a non-ASCII
    // codepoint here and is left alone.
    if (hasNonAscii(skel)) return [];

    return [
      {
        code: "homograph_latin_skeleton",
        detail:
          `registrable domain '${input}' is non-Latin but its UTS#39 confusable ` +
          `skeleton is pure ASCII-Latin ('${skel.normalize("NFC")}') — a whole-label ` +
          "homograph masquerading as an ASCII domain",
      },
    ];
  },
};
