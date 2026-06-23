import type { InspectionContext } from "./types.js";
import { BRAND_DOMAINS } from "../data/brands.js";

/**
 * Shared building blocks for the brand-family detectors (`brand_lookalike`,
 * `brand_soundsquat`, `brand_bitsquat`). These derived sets,
 * the significant-label helpers, and the ASCII-registrable preamble were
 * duplicated byte-for-byte across those files; they live here once so all brand
 * detectors share one source of truth.
 */

/** Brand registrable domains as a Set for O(1) exact-match membership. */
export const BRAND_DOMAIN_SET: ReadonlySet<string> = new Set(BRAND_DOMAINS);

/** The brand's significant (registrable) label, left of the public suffix. */
export function significantLabel(brandDomain: string): string {
  const dot = brandDomain.indexOf(".");
  return dot === -1 ? brandDomain : brandDomain.slice(0, dot);
}

/** The length of the brand's significant (registrable) label. */
export function significantLabelLength(brandDomain: string): number {
  const dot = brandDomain.indexOf(".");
  return dot === -1 ? brandDomain.length : dot;
}

/** Set of brand significant labels (lowercase) for exact-label skip. */
export const BRAND_LABEL_SET: ReadonlySet<string> = new Set(
  BRAND_DOMAINS.map((d) => significantLabel(d)),
);

/** True when `domain` is itself a watchlist brand registrable domain. */
export function isExactBrandDomain(domain: string): boolean {
  return BRAND_DOMAIN_SET.has(domain);
}

/**
 * The shared brand-family preamble: returns the lower-cased registrable domain
 * when it is present, non-IP, pure-ASCII, and NOT itself an exact brand domain;
 * otherwise null. Non-ASCII (IDN) hosts belong to the confusable / IDNA
 * detectors, and an exact brand IS the brand, so neither is a near-miss
 * candidate here.
 */
export function asciiRegistrableBrandCandidate(
  ctx: InspectionContext,
): string | null {
  const input = ctx.registrableDomain;
  if (!input || ctx.isIp) return null;
  if (!/^[\x00-\x7f]+$/.test(input)) return null;
  const raw = ctx.registrableDomainLower!; // identical to input.toLowerCase()
  if (BRAND_DOMAIN_SET.has(raw)) return null;
  return raw;
}
