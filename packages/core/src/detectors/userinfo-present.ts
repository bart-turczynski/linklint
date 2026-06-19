import type { Detector } from "./types.js";

/**
 * FR-D-6 — userinfo / authority deception (`paypal.com@evil.com`). Scoring.
 * Surfaces the real host so the deception is explained, not just flagged.
 */
export const userinfoPresent: Detector = {
  id: "userinfo_present",
  layer: "lexical",
  run(ctx) {
    if (ctx.userinfo === null || ctx.userinfo === "") return [];
    const realHost = ctx.host === "" ? "(none)" : ctx.host;
    return [
      {
        code: "userinfo_present",
        detail: `authority hidden behind '${ctx.userinfo}@'; the real host is '${realHost}'`,
      },
    ];
  },
};
