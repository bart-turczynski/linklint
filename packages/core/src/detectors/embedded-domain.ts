import type { Detector } from "./types.js";
import { looksLikeRegistrableDomain } from "../parse/psl.js";

/**
 * FR-D-8 — embedded domain in subdomain (`paypal.com.spoof.info`). Scoring.
 * Purely lexical in v1 (no DNS resolution of the embedded domain — FR-D-14):
 * uses the PSL to spot an authority-looking label sequence left of the real
 * registrable domain.
 */

/**
 * The eight TLDs that existed before the domain name system was opened to
 * expansion: the seven of RFC 920 (1984) plus `int` (1988). Closed history — a
 * finished list of delegations, not a judgment about which strings look
 * infrastructural. That is what makes it admissible here where a curated word
 * list would not be (architecture §6, `LINK-cqdrdvfu`).
 */
const LEGACY_GTLDS = new Set(["com", "net", "org", "edu", "gov", "mil", "int", "arpa"]);

/**
 * Does this window's public suffix belong to a class that carries signal?
 *
 * A window that reaches here is exactly an eTLD+1, so its public suffix is
 * everything right of the first dot — no second PSL lookup needed. Two classes
 * qualify, and both were measured rather than assumed (`LINK-kgiviycg`,
 * re-measured under `LINK-vuqdzmzy`; architecture §6.1.6):
 *
 *  - a MULTI-LABEL suffix under a two-letter ccTLD — `paypal.co.uk.evil.com`,
 *    `amazon.co.jp.evil.com`. The most discriminative class in the whole rule.
 *  - a bare LEGACY gTLD — `paypal.com.spoof.info`, `hmrc.gov.evil.com`. The
 *    canonical FR-D-8 shape.
 *
 * Everything else is skipped, on two separate grounds:
 *
 *  - A BARE TWO-LETTER suffix is a region code. IANA reserves every two-letter
 *    TLD for an ISO 3166-1 alpha-2 country code, and those same codes are what
 *    the universal regional-subdomain convention puts left of a registrable
 *    domain: `www.eu.playstation.com`, `api.uk.example.com`. Such a window is
 *    fully accounted for by ordinary naming — `normalize(host) === host`, every
 *    conforming reader resolves `playstation.com`, and the string makes no
 *    claim about itself that fails. Under architecture §1.1 that is not a
 *    scoring finding (`LINK-pbilvjuv`).
 *  - An EXPANSION-ERA suffix — everything delegated from the 2000 round onward,
 *    including the pre-2012 sponsored round (`.info`, `.travel`, `.post`,
 *    `.jobs`, `.asia`) and the 2012 New gTLD Program (`.cloud`, `.dev`,
 *    `.news`, `.app`, and every brand gTLD) — is where hosting providers and
 *    internal naming conventions live, on both sides of the ledger.
 *    `console.cloud.google.com` and `z1.web.core.windows.net` are the same kind
 *    of string, and the measurement says so: a window in this class is 2–4×
 *    MORE likely on a benign host than on a phishing one (`LINK-vuqdzmzy`).
 *
 * The discriminator is the suffix's DELEGATION ERA, which is closed history,
 * not a curated list of infrastructure-looking words — no per-word sub-class
 * survived measurement, and a word list is the self-confirming trap §6 warns
 * about. A multi-label suffix under an expansion gTLD (`in-addr.arpa`, reverse
 * DNS) is skipped too: the multi-label carve-out is for ccTLDs, which is the
 * class that was measured.
 *
 * Skipped windows are SKIPPED, not returned, so the scan continues to their
 * right. That is load-bearing for the brand gTLDs: `appleid.apple.com.evil.tk`
 * passes over `appleid.apple` and reports `apple.com` instead.
 */
const suffixCarriesSignal = (candidate: string): boolean => {
  const suffix = candidate.slice(candidate.indexOf(".") + 1);
  const dot = suffix.lastIndexOf(".");
  if (dot === -1) return LEGACY_GTLDS.has(suffix.toLowerCase());
  return /^[a-z]{2}$/i.test(suffix.slice(dot + 1));
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
    // (`sub.domain.example.co.uk`) from flagging, and the suffix-class gate
    // above keeps the regional-subdomain convention (`www.eu.playstation.com`)
    // and expansion-era infrastructure naming (`console.cloud.google.com`) from
    // flagging. Skipped windows are SKIPPED, not returned, so a real embedded
    // domain further right is still found: `www.eu.paypal.com.evil.info` and
    // `appleid.apple.com.evil.tk` both report the `.com` window.
    for (let len = n; len >= 2; len--) {
      for (let start = 0; start + len <= n; start++) {
        const candidate = labels.slice(start, start + len).join(".");
        if (looksLikeRegistrableDomain(candidate) && suffixCarriesSignal(candidate)) {
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
