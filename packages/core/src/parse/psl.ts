import { parse as tldtsParse } from "tldts";

/**
 * PSL-derived view of a host. Backed by tldts (bundles a Public Suffix List
 * snapshot; version pinned in dataVersions). See FR-IN-2 / FR-D-8 / A4.
 */
export interface PslResult {
  /** Registrable domain (eTLD+1), or null for IPs / unknown / hostless. */
  registrableDomain: string | null;
  /** Public suffix (eTLD), or null. */
  publicSuffix: string | null;
  /** Subdomain labels left of the registrable domain, or null. */
  subdomain: string | null;
  /** True when the host is an IP literal (v4 or v6). */
  isIp: boolean;
}

/**
 * Analyze a (already invisible-stripped) host string. ICANN rules only — private
 * suffixes (e.g. github.io) are treated as registrable so that an embedded
 * `github.io` is still seen as a domain by FR-D-8.
 */
export function analyzeHost(host: string): PslResult {
  const r = tldtsParse(host, { allowPrivateDomains: false, detectIp: true });
  return {
    registrableDomain: r.domain,
    publicSuffix: r.publicSuffix,
    subdomain: r.subdomain,
    isIp: r.isIp ?? false,
  };
}

/**
 * Does this string, on its own, look like a registrable domain (eTLD+1)?
 * Used by FR-D-8 to spot authority-looking labels embedded in a subdomain.
 */
export function looksLikeRegistrableDomain(candidate: string): boolean {
  const r = tldtsParse(candidate, { allowPrivateDomains: false });
  // Require a real ICANN-listed suffix: otherwise tldts's implicit wildcard rule
  // makes any two-label string (e.g. "sub.domain") look like a registrable
  // domain, producing embedded-domain false positives.
  return r.domain === candidate && r.isIcann === true && !r.isIp;
}

/**
 * Registrable domain under the PRIVATE-inclusive view: the same lookup as
 * {@link analyzeHost} with the PSL's PRIVATE section switched on, so a
 * multi-tenant platform's tenants stay distinct (`alice.github.io` and
 * `mallory.github.io` resolve to themselves rather than collapsing onto
 * `github.io`). Returns `null` when the host has no registrable domain under
 * that view (an IP literal, an unlisted suffix, a hostless input).
 *
 * DELIBERATELY NOT wired into {@link analyzeHost} or `HostFacts`. Architecture
 * §6.1 declined that seam — it would add a second PSL lookup to every
 * `inspect()` against the sub-5 ms budget, and put two similarly-named fields
 * with a subtle correctness difference in front of every future detector. This
 * is a separate function for the one production consumer that needs the other
 * view (`compare/compare-urls.ts`), which is not on the `inspect()` path, so
 * the declined seam stays declined and the hot path is untouched.
 *
 * No caching, on purpose (pslr D19): tldts owns its own lookup structure and a
 * memo here would be a second cache with a second invalidation story.
 */
export function privateRegistrableDomain(host: string): string | null {
  return tldtsParse(host, { allowPrivateDomains: true, detectIp: true }).domain;
}
