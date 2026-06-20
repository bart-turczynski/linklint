import type { Detector } from "./types.js";
import { ASCII_DIGIT_HOMOGLYPHS } from "../data/ascii-confusables.js";

/**
 * J4 — `ascii_homoglyph` (Epic J). SCORING, low weight (0.2).
 *
 * Flags SAME-SCRIPT (Latin/ASCII) look-alikes that the cross-script detectors
 * miss: `mixed_script` and `confusable_char` only fire when two *different*
 * scripts mix, so a host built entirely from ASCII — `g00gle`, `paypa1`,
 * `micr0soft` — sails past them. This is the general, brand-free structural
 * signal: a digit standing in for the letter it resembles, embedded inside an
 * otherwise alphabetic word.
 *
 * Scope is deliberately narrow to keep precision (SC-2) — the issue's standing
 * concern is "do not flag legitimate domains with digits" (`s3`, `web3`, `mp3`,
 * `bet365`, `7-eleven`). A label flags only when ALL of these hold:
 *   - it is pure ASCII alphanumeric (no hyphen/other), length ≥ 5;
 *   - its FIRST character is a letter (a leading digit reads as an obvious
 *     number — `1password`, `0day` — not a disguised letter);
 *   - every digit it contains is one of the unambiguous letter-shaped digits
 *     `0`→o, `1`→l, `5`→s (any `2/3/4/6/7/8/9` disqualifies the whole label, so
 *     `s3`, `route53`, `i18n`, `blink182` never flag);
 *   - letters outnumber those digits (a mostly-numeric label is a code, not a
 *     word);
 * and mapping the digits back yields a fully alphabetic skeleton, surfaced in
 * the detail (`g00gle` → `google`).
 *
 * LETTER-multigraph confusions (`rn`→m, `vv`→w) are intentionally NOT handled
 * here: generically they fire on ordinary words (`modern`, `return`, `savvy`)
 * and can only be told apart from an attack by distance to a known brand — that
 * belongs to the brand-aware layer (Epic G). Confirmed brand matches also escalate
 * there; this base signal stays low so a lone digit-in-word lands `low` and only
 * matters in combination.
 */

// Letter-shaped digits and the letter each maps to for the readable skeleton
// come from the shared `ASCII_DIGIT_HOMOGLYPHS` map (data/ascii-confusables.ts)
// — the single source of truth this detector and G2 `brand_lookalike` share.

export const asciiHomoglyph: Detector = {
  id: "ascii_homoglyph",
  layer: "lexical",
  run(ctx) {
    if (ctx.isIp || ctx.hostLabels.length === 0) return [];

    const hits: { label: string; skeleton: string }[] = [];
    for (const raw of ctx.hostLabels) {
      const label = raw.toLowerCase();
      if (label.length < 5) continue;
      if (!/^[a-z0-9]+$/.test(label)) continue; // ASCII alnum only, no hyphen
      if (!/^[a-z]/.test(label)) continue; // first char must be a letter

      let letters = 0;
      let digits = 0;
      let mappable = true;
      let skeleton = "";
      for (const ch of label) {
        if (ch >= "a" && ch <= "z") {
          letters++;
          skeleton += ch;
        } else {
          // a digit
          const mapped = ASCII_DIGIT_HOMOGLYPHS[ch];
          if (mapped === undefined) {
            mappable = false;
            break;
          }
          digits++;
          skeleton += mapped;
        }
      }
      if (!mappable || digits === 0) continue;
      if (letters <= digits) continue; // mostly-numeric label is a code, not a word

      hits.push({ label, skeleton });
    }

    if (hits.length === 0) return [];

    const parts = hits.map((h) => `'${h.label}' (reads as '${h.skeleton}')`);
    return [
      {
        code: "ascii_homoglyph",
        detail:
          "host uses ASCII digit look-alikes for letters — same-script disguise that " +
          `cross-script checks miss: ${parts.join(", ")}`,
      },
    ];
  },
};
