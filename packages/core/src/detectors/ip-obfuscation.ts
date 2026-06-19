import type { Detector } from "./types.js";
import { analyzeIpv4 } from "../parse/ip.js";

/**
 * FR-D-7 — IP-address obfuscation (decimal/octal/hex/dotless). Scoring. A
 * canonical dotted-decimal IP is NOT flagged; only non-canonical encodings are.
 * Renders the canonical form so the real destination is explained.
 */
export const ipObfuscation: Detector = {
  id: "ip_obfuscation",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "") return [];
    const ip = analyzeIpv4(ctx.host);
    if (!ip || !ip.obfuscated) return [];
    return [
      {
        code: "ip_obfuscation",
        detail: `host '${ctx.host}' is an obfuscated IP; canonical form is ${ip.canonical}`,
      },
    ];
  },
};
