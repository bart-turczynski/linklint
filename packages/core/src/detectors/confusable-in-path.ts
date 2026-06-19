import type { Confusable } from "../schema/types.js";
import type { Detector } from "./types.js";
import { findConfusables } from "../unicode/confusables.js";

/**
 * FR-D-12 — confusable characters in the path / query. Informational only
 * (weight 0, FR-D-16): annotation, not a flag.
 */
export const confusableInPath: Detector = {
  id: "confusable_in_path",
  layer: "lexical",
  run(ctx) {
    const confusables: Confusable[] = [
      ...findConfusables(ctx.path, "path"),
      ...(ctx.query ? findConfusables(ctx.query, "query") : []),
    ];
    if (confusables.length === 0) return [];
    const n = confusables.length;
    return [
      {
        code: "confusable_in_path",
        detail: `${n} confusable character${n > 1 ? "s" : ""} in path/query`,
        confusables,
      },
    ];
  },
};
