import type { Detector } from "./types.js";
import { hasMalformedPunycode } from "../unicode/idna.js";

/**
 * E5 — malformed punycode. A host with an `xn--` (ACE) label that does not
 * decode to a valid U-label is a lexical anomaly: it is not a registrable IDN
 * and never appears in legitimate links. Low weight — anomalous, but not
 * inherently an attack on its own. Valid IDNs (including uppercase ACE, which
 * round-trips after UTS-46 case-folding) are unaffected.
 */
export const punycodeMalformed: Detector = {
  id: "punycode_malformed",
  layer: "lexical",
  run(ctx) {
    if (ctx.host === "" || !hasMalformedPunycode(ctx.host)) return [];
    return [
      {
        code: "punycode_malformed",
        detail: `host '${ctx.host}' has an xn-- label that does not decode to a valid IDN`,
      },
    ];
  },
};
