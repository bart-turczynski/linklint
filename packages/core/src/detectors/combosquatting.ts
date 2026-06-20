import type { Detector, DetectorFinding } from "./types.js";
import { isBrandKeyword } from "../data/brands.js";
import { isExactBrandDomain } from "./brand-utils.js";

/**
 * `brand_combosquat`. SCORING, weight 0.4.
 *
 * Detects COMBOSQUATTING: a watchlist brand keyword GLUED to an additive
 * (non-brand) token inside a single host label — `paypal-secure.com`,
 * `login-paypal.com`, `secure-paypal-login.net`, `paypal-verify.evil.com`.
 *
 * Per IDEAS-ADDENDUM §4 this structure is MORE common than character typos and
 * is INVISIBLE to edit distance: the host is not a near-miss of the brand
 * domain, so `brand_lookalike` / `brand_homoglyph` never catch it. This
 * detector complements them with pure string ops over the host.
 *
 * ── Token boundary (the key precision lever) ───────────────────────────────
 * A brand keyword counts as PRESENT only when it is a SEPARATOR-DELIMITED token.
 * Host labels are split on `-` (hyphen) and the implicit `.` label boundary.
 * `paypal-secure` -> tokens [`paypal`, `secure`]; `login-paypal` ->
 * [`login`, `paypal`]. This is what stops `amazonaws.com` (a single concatenated
 * token `amazonaws`, legitimate AWS) and similar substrings from firing — we do
 * NOT do bare substring matching.
 *
 * ── What fires (the deliberate COMBINATION) ────────────────────────────────
 * A genuine combo: within ONE hyphenated label, a brand keyword token PLUS at
 * least one additional NON-brand token. A lone label that is exactly a brand
 * keyword (e.g. host label `paypal` as a subdomain of `evil.com`) is NOT a
 * combosquat — that is `embedded_domain_in_subdomain` / `brand_in_path`
 * territory. Combosquatting specifically needs the brand keyword GLUED to an
 * additive token via a hyphen, which is the unambiguous, high-precision case.
 *
 * Both the registrable label and any subdomain labels are inspected, so
 * `paypal-secure.com` (registrable label `paypal-secure`) and
 * `paypal-verify.evil.com` (subdomain label `paypal-verify`) both fire.
 *
 * ── Precision (SC-2, precision=1 discipline) ───────────────────────────────
 * The legitimate brand never fires: if the input's registrable domain is itself
 * a watchlist brand domain (`paypal.com`, and its own subdomains like
 * `login.paypal.com` whose registrable domain is still `paypal.com`), the brand
 * is legitimately using its own keyword on its own domain, so we skip.
 *
 * ── No overlap with existing detectors ─────────────────────────────────────
 * - `brand_in_path` fires on a brand in the PATH/QUERY of an unrelated
 *   host — a DIFFERENT location (host vs path). No overlap.
 * - `brand_lookalike` / `brand_homoglyph` fire on edit-distance / digit
 *   folds of the registrable domain; combosquats are not near-misses, so they
 *   are complementary, never duplicative.
 * - Stacking with `embedded_domain_in_subdomain` is acceptable when both
 *   genuinely apply (distinct codes, distinct structures).
 */

export const combosquatting: Detector = {
  id: "brand_combosquat",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.isIp) return [];
    if (!ctx.host) return [];

    // Never fire on the legitimate brand: the brand owns its own keyword on its
    // own registrable domain (covers `paypal.com` and `login.paypal.com`).
    const registrable = ctx.registrableDomainLower;
    if (registrable && isExactBrandDomain(registrable)) return [];

    for (const label of ctx.hostLabels) {
      const lower = label.toLowerCase();
      // Require a hyphen-glued combination: a single label split on `-` into
      // multiple tokens. A lone (non-hyphenated) label is not a combosquat.
      if (!lower.includes("-")) continue;
      const tokens = lower.split("-").filter((t) => t !== "");
      if (tokens.length < 2) continue;

      const brandTokens = tokens.filter((t) => isBrandKeyword(t));
      const additiveTokens = tokens.filter((t) => !isBrandKeyword(t));
      // Genuine combination: at least one brand keyword AND at least one
      // additive non-brand token in the same hyphenated label.
      if (brandTokens.length === 0 || additiveTokens.length === 0) continue;

      const brand = brandTokens[0]!;
      return [
        {
          code: "brand_combosquat",
          detail:
            `host label '${label}' combines the brand keyword '${brand}' with ` +
            `additional token(s) — a combosquat of an unrelated registrable domain ` +
            `'${ctx.registrableDomain ?? ctx.host}'`,
        },
      ];
    }

    return [];
  },
};
