import type { Detector } from "./types.js";
import { analyzeMalformedPunycode } from "../unicode/punycode.js";

/**
 * Malformed punycode. A host with an `xn--` (ACE) label that does not
 * decode to a valid U-label is a lexical anomaly: it is not a registrable IDN
 * and never appears in legitimate links. Low weight — anomalous, but not
 * inherently an attack on its own. Valid IDNs (including uppercase ACE, which
 * round-trips after UTS-46 case-folding) are unaffected.
 *
 * The reason code is a stable `punycode_malformed`; the DETAIL carries a specific
 * failure sub-code from the RFC 3492 taxonomy (P1 / LINK-dynjdiax) — e.g.
 * `punycode_overflow`, `truncated_punycode_input`, `non_canonical_encoding` — so
 * consumers see WHY the label is malformed, not just that it is. Firing is
 * unchanged (still gated by tr46), so no scoring behavior changes.
 */
export const punycodeMalformed: Detector = {
  id: "punycode_malformed",
  layer: "lexical",
  run(ctx) {
    const m = analyzeMalformedPunycode(ctx.host);
    if (m === null) return [];
    return [
      {
        code: "punycode_malformed",
        detail:
          `host '${ctx.host}' has a malformed xn-- label '${m.label}': ` +
          `${m.subCode} (${m.description})`,
      },
    ];
  },
};
