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
  return r.domain === candidate && !r.isIp;
}
