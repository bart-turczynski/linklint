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
    const labels = ctx.subdomainLabels;
    const n = labels.length;
    // Scan ALL contiguous windows of subdomain labels — not just suffixes — so a
    // brand domain with filler labels between it and the real eTLD+1 is still
    // caught (e.g. `paypal.com.login.evil.com`). Report the longest /
    // most-specific window that is itself a registrable domain; the ICANN-suffix
    // gate in looksLikeRegistrableDomain keeps deep legitimate subdomains
    // (`sub.domain.example.co.uk`) from flagging.
    for (let len = n; len >= 2; len--) {
      for (let start = 0; start + len <= n; start++) {
        const candidate = labels.slice(start, start + len).join(".");
        if (looksLikeRegistrableDomain(candidate)) {
          return [
            {
              code: "embedded_domain_in_subdomain",
              detail: `'${candidate}' appears in the subdomain; the real registrable domain is '${ctx.registrableDomain}'`,
            },
          ];
        }
      }
    }
    return [];
  },
};
