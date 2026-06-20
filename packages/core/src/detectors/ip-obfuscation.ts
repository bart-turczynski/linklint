import type { Detector } from "./types.js";
import { analyzeIpv4, analyzeIpv6 } from "../parse/ip.js";

/**
 * FR-D-7 — IP-address obfuscation. Scoring. A canonical dotted-decimal
 * IPv4 or canonical IPv6 literal is NOT flagged; only non-canonical encodings
 * are, with the canonical form rendered so the real destination is explained.
 *
 *  - IPv4: decimal / octal / hex / dotless (`2130706433`, `0x7f.0.0.1`).
 *  - IPv6: non-canonical literals (leading zeros, uppercase, uncompressed
 *    zero runs) and IPv4-embedding forms (`[::ffff:127.0.0.1]`) — the SSRF
 *    masquerade where a validator sees IPv6 but the resolver reaches an IPv4.
 */
export const ipObfuscation: Detector = {
  id: "ip_obfuscation",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "") return [];

    const ip4 = analyzeIpv4(ctx.host);
    if (ip4) {
      if (!ip4.obfuscated) return []; // canonical IPv4
      return [
        {
          code: "ip_obfuscation",
          detail: `host '${ctx.host}' is an obfuscated IP; canonical form is ${ip4.canonical}`,
        },
      ];
    }

    const ip6 = analyzeIpv6(ctx.host);
    if (ip6 && ip6.obfuscated) {
      const embed = ip6.embeddedIpv4 ? ` (embeds IPv4 ${ip6.embeddedIpv4})` : "";
      return [
        {
          code: "ip_obfuscation",
          detail:
            `host '[${ctx.host}]' is a non-canonical IPv6 literal${embed}; ` +
            `canonical form is [${ip6.canonical}]`,
        },
      ];
    }

    return [];
  },
};
