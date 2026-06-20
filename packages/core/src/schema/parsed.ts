/** Parsed URL components surfaced on an `ok` result. `null` on invalid input. */
export interface ParsedUrl {
  /** Lower-cased scheme without the trailing colon, or `null` if none present. */
  scheme: string | null;
  /** The userinfo (`user:pass`) segment before `@`, or `null`. */
  userinfo: string | null;
  /** The host as it appears in the authority (U-label form where applicable). */
  effectiveHost: string | null;
  /** Registrable domain (eTLD+1) per the Public Suffix List, or `null`. */
  registrableDomain: string | null;
  /** Public suffix (eTLD) per the PSL, or `null`. */
  publicSuffix: string | null;
  /** Subdomain labels left of the registrable domain (may be empty string). */
  subdomain: string | null;
  /** Host split into labels, left-to-right. Empty for IP / hostless inputs. */
  hostLabels: string[];
  /** Numeric port, or `null` when not explicitly present. */
  port: number | null;
  /** Path component (may be empty string). */
  path: string;
  /** Query string without the leading `?`, or `null`. */
  query: string | null;
  /** Fragment without the leading `#`, or `null`. */
  fragment: string | null;
  /** True when the effective host is an IP literal (v4 or v6). */
  isIp: boolean;
}
