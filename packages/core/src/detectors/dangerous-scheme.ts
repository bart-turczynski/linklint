import type { Detector } from "./types.js";

/** Schemes that can execute or embed content (FR-D-11). */
const DANGEROUS_SCHEMES = new Set(["javascript", "data", "blob", "file", "vbscript"]);

/**
 * FR-D-11 — dangerous scheme. Highest single weight (0.9): these schemes are
 * almost never a legitimate link to follow.
 */
export const dangerousScheme: Detector = {
  id: "dangerous_scheme",
  layer: "lexical",
  run(ctx) {
    if (!ctx.scheme || !DANGEROUS_SCHEMES.has(ctx.scheme)) return [];
    return [
      {
        code: "dangerous_scheme",
        detail: `scheme '${ctx.scheme}:' can execute or embed content`,
      },
    ];
  },
};
