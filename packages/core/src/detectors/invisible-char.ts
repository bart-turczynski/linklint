import type { Detector } from "./types.js";
import { codepointOf, isInvisibleNonBidi } from "../unicode/format-chars.js";

/**
 * FR-D-4 — invisible / zero-width / control characters anywhere in the URL.
 * Scoring. Bidi controls are excluded here and reported by bidi_override.
 */
export const invisibleChar: Detector = {
  id: "invisible_char",
  layer: "lexical",
  run(ctx) {
    const found: string[] = [];
    for (const ch of ctx.input) {
      if (isInvisibleNonBidi(ch)) found.push(ch);
    }
    if (found.length === 0) return [];
    const codepoints = [...new Set(found.map(codepointOf))];
    const n = found.length;
    return [
      {
        code: "invisible_char",
        detail: `${n} invisible/control character${n > 1 ? "s" : ""} in URL (${codepoints.join(", ")})`,
      },
    ];
  },
};
