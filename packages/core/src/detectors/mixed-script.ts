import type { Detector } from "./types.js";
import { analyzeLabelScripts } from "../unicode/scripts.js";

/**
 * FR-D-3 — script-mixing within a single host label. Scoring. This is the
 * cross-script de-noiser: legitimate IDNs are single-script (or
 * script-compatible), so mixing incompatible scripts inside one label is the
 * homograph-attack signal that actually scores (FR-D-16). Operates on the
 * decoded Unicode host.
 */
export const mixedScript: Detector = {
  id: "mixed_script",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "") return [];
    const labels = ctx.hostUnicode.replace(/\.$/, "").split(".");
    for (const label of labels) {
      const { mixed, scripts } = analyzeLabelScripts(label);
      if (mixed) {
        return [
          {
            code: "mixed_script",
            detail: `host label '${label}' mixes scripts: ${scripts.join(" + ")}`,
          },
        ];
      }
    }
    return [];
  },
};
