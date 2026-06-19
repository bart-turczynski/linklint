import type { Detector } from "./types.js";
import { findConfusables } from "../unicode/confusables.js";

/**
 * FR-D-2 — per-character confusable annotation in the host. Informational only
 * (weight 0, FR-D-16): raw confusable annotation must not score, or legitimate
 * single-script IDNs would be penalized. Scans the decoded Unicode host so
 * confusables hidden inside `xn--` punycode are surfaced.
 */
export const confusableChar: Detector = {
  id: "confusable_char",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "") return [];
    const confusables = findConfusables(ctx.hostUnicode, "host");
    if (confusables.length === 0) return [];
    const n = confusables.length;
    return [
      {
        code: "confusable_char",
        detail: `${n} confusable character${n > 1 ? "s" : ""} in host`,
        confusables,
      },
    ];
  },
};
