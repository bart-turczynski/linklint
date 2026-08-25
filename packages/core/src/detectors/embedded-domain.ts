import type { Detector } from "./types.js";
import { looksLikeRegistrableDomain } from "../parse/psl.js";

/**
 * FR-D-8 — embedded domain in subdomain (`paypal.com.spoof.info`). Scoring.
 * Purely lexical in v1 (no DNS resolution of the embedded domain — FR-D-14):
 * uses the PSL to spot an authority-looking label sequence left of the real
 * registrable domain.
 */

/**
 * Is this window's public suffix a bare two-letter label?
 *
 * A window that reaches here is exactly an eTLD+1, so its public suffix is
 * everything right of the first dot — no second PSL lookup needed.
 *
 * IANA permanently reserves every two-letter TLD for an ISO 3166-1 alpha-2
 * country code, and those same codes are what the universal regional-subdomain
 * convention puts left of a registrable domain: `www.eu.playstation.com`,
 * `api.uk.example.com`, `store.jp.example.com`. A window ending in one is
 * therefore fully accounted for by ordinary naming — `normalize(host) === host`,
 * every reader resolves `playstation.com`, and the string makes no claim about
 * itself that fails. Under architecture §1.1 that is not a scoring finding, so
 * the window is skipped and the scan continues to the right (LINK-pbilvjuv).
 *
 * The test is on the SUFFIX, not the window: a multi-label ccTLD suffix such as
 * `co.uk` (`paypal.co.uk.evil.com`) is not a bare region code and still fires.
 */
const isRegionCodeSuffix = (candidate: string): boolean => {
  const suffix = candidate.slice(candidate.indexOf(".") + 1);
  return /^[a-z]{2}$/i.test(suffix);
};

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
    // (`sub.domain.example.co.uk`) from flagging, and the region-code gate below
    // keeps the regional-subdomain convention (`www.eu.playstation.com`) from
    // flagging. Region-code windows are SKIPPED, not returned, so a real
    // embedded domain further right is still found: `www.eu.paypal.com.evil.info`
    // reports `paypal.com`.
    for (let len = n; len >= 2; len--) {
      for (let start = 0; start + len <= n; start++) {
        const candidate = labels.slice(start, start + len).join(".");
        if (looksLikeRegistrableDomain(candidate) && !isRegionCodeSuffix(candidate)) {
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
