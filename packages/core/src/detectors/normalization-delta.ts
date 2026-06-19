import type { Detector } from "./types.js";
import { hasNormalizationDelta, toAscii, toUnicode } from "../unicode/idna.js";

/**
 * FR-D-1 — normalization / punycode delta. Informational only (weight 0,
 * FR-D-15): any IDN triggers it, so on its own it must never raise severity.
 */
export const normalizationDelta: Detector = {
  id: "normalization_delta",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "" || !hasNormalizationDelta(ctx.host)) return [];
    const ace = toAscii(ctx.host);
    const uni = toUnicode(ctx.host);
    return [
      {
        code: "normalization_delta",
        detail: `host '${uni}' differs from its ACE form '${ace}'`,
      },
    ];
  },
};
