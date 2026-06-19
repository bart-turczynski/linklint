import type { Detector } from "./types.js";
import { isRiskyTld } from "../data/risky-tlds.js";

/**
 * FR-D-9 — high-abuse / extension-confusable TLD. Low-weight scoring (0.15) so
 * it is only meaningful in combination, never a flag on its own.
 */
export const riskyTld: Detector = {
  id: "risky_tld",
  layer: "lexical",
  run(ctx) {
    if (!ctx.publicSuffix) return [];
    const tld = ctx.publicSuffix.split(".").pop()!;
    if (!isRiskyTld(tld)) return [];
    return [
      {
        code: "risky_tld",
        detail: `TLD '.${tld}' is high-abuse or extension-confusable`,
      },
    ];
  },
};
