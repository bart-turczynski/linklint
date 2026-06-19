import type { Detector } from "./types.js";
import { looksLikeRegistrableDomain } from "../parse/psl.js";

/**
 * FR-D-8 — embedded domain in subdomain (`paypal.com.spoof.info`). Scoring.
 * Purely lexical in v1 (no DNS resolution of the embedded domain — FR-D-14):
 * uses the PSL to spot an authority-looking label sequence left of the real
 * registrable domain.
 */
export const embeddedDomain: Detector = {
  id: "embedded_domain_in_subdomain",
  layer: "lexical",
  run(ctx) {
    if (!ctx.registrableDomain || !ctx.subdomain) return [];
    const labels = ctx.subdomain.split(".");
    // Longest -> shortest suffix; report the most-specific registrable domain.
    for (let i = 0; i <= labels.length - 2; i++) {
      const candidate = labels.slice(i).join(".");
      if (looksLikeRegistrableDomain(candidate)) {
        return [
          {
            code: "embedded_domain_in_subdomain",
            detail: `'${candidate}' appears in the subdomain; the real registrable domain is '${ctx.registrableDomain}'`,
          },
        ];
      }
    }
    return [];
  },
};
