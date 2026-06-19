import type { Detector } from "./types.js";
import { codepointOf, isBidiControl } from "../unicode/format-chars.js";

/**
 * FR-D-5 — bidirectional / RTL override characters anywhere in the URL. Scoring.
 * These visually reorder text (e.g. flipping a file extension).
 */
export const bidiOverride: Detector = {
  id: "bidi_override",
  layer: "lexical",
  run(ctx) {
    const found: string[] = [];
    for (const ch of ctx.input) {
      if (isBidiControl(ch)) found.push(ch);
    }
    if (found.length === 0) return [];
    const codepoints = [...new Set(found.map(codepointOf))];
    return [
      {
        code: "bidi_override",
        detail: `bidirectional override character(s) in URL (${codepoints.join(", ")})`,
      },
    ];
  },
};
