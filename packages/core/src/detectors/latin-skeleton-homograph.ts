import type { Detector, DetectorFinding } from "./types.js";
import { skeleton } from "../unicode/skeleton.js";

/**
 * `homograph_latin_skeleton`. Detects non-ASCII registrable domains whose
 * UTS#39 confusable skeleton is pure ASCII-Latin. Detailed rationale and
 * examples live in docs/reason-codes.md.
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
