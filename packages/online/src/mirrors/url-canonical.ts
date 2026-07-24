/**
 * Shared exact-URL canonicalization for caller-owned feed lookups (Epic M mirrors).
 *
 * URLhaus and PhishTank both list *exact* malicious URLs, so a match must be
 * exact — a different path or query is a different URL, and the host is never
 * broadened. Both the indexed records and the query URL pass through this single
 * function, which normalizes only the parts that are semantically case-/form-
 * insensitive (scheme, host, default port) and preserves path and query verbatim.
 * That makes matching robust to trivial input differences (an upper-case host, an
 * explicit `:443`) without ever manufacturing a host-only or path-broadened match.
 */

import { domainToASCII } from "node:url";

/**
 * Canonicalize a URL for exact feed comparison, or return `null` when it is not a
 * parseable absolute `http(s)` URL. Scheme and host are lower-cased, the host is
 * converted to its IDN A-label, a default port for the scheme is dropped, and the
 * fragment is removed (it never reaches the server). Path and query are preserved
 * exactly.
 */
export function canonicalizeUrl(raw: string): string | null {
  if (typeof raw !== "string" || raw.trim() === "") return null;

  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }

  const scheme = url.protocol.toLowerCase();
  if (scheme !== "http:" && scheme !== "https:") return null;

  // URL already lower-cases and punycodes the host; re-run domainToASCII to
  // canonicalize any residual IDN form and reject an empty host.
  const host = domainToASCII(url.hostname).toLowerCase();
  if (host === "") return null;

  const port = defaultPort(scheme) === url.port || url.port === "" ? "" : `:${url.port}`;
  // `url.pathname` keeps the leading slash and exact case; `url.search` keeps `?`.
  return `${scheme}//${host}${port}${url.pathname}${url.search}`;
}

function defaultPort(scheme: string): string {
  return scheme === "https:" ? "443" : "80";
}
