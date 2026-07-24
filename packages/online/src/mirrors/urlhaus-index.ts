/**
 * URLhaus exact-URL canonicalization and lookup index (LINK-ifpdilfn, M4b).
 *
 * URLhaus lists *exact* malware-distribution URLs, so a match must be exact — a
 * different path or query is a different URL, and the host is never broadened.
 * Both the indexed records and the query URL pass through the identical {@link
 * canonicalizeUrl}, which normalizes only the parts that are semantically
 * case-/form-insensitive (scheme, host, default port) and preserves path and
 * query verbatim. That makes matching robust to trivial input differences (an
 * upper-case host, an explicit `:443`) without ever manufacturing a host-only or
 * path-broadened match.
 *
 * The index is built once from a caller-owned snapshot and queried locally; the
 * enricher performs no network I/O at check time.
 */

import { domainToASCII } from "node:url";

import type { UrlhausIndex, UrlhausRecord, UrlhausSnapshot } from "./types.js";

/**
 * Canonicalize a URL for exact URLhaus comparison, or return `null` when it is
 * not a parseable absolute `http(s)` URL. Scheme and host are lower-cased, the
 * host is converted to its IDN A-label, a default port for the scheme is dropped,
 * and the fragment is removed (it never reaches the server). Path and query are
 * preserved exactly.
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

/**
 * Build an exact-URL lookup index over a snapshot. Records whose URL cannot be
 * canonicalized are dropped from the index (they can never be matched exactly).
 * When two records canonicalize to the same URL, the first one wins.
 */
export function createUrlhausIndex(snapshot: UrlhausSnapshot): UrlhausIndex {
  const byUrl = new Map<string, UrlhausRecord>();
  for (const record of snapshot.records) {
    const key = canonicalizeUrl(record.url);
    if (key !== null && !byUrl.has(key)) byUrl.set(key, record);
  }

  return {
    metadata: snapshot.metadata,
    lookup(url: string): UrlhausRecord | null {
      const key = canonicalizeUrl(url);
      if (key === null) return null;
      return byUrl.get(key) ?? null;
    },
  };
}

function defaultPort(scheme: string): string {
  return scheme === "https:" ? "443" : "80";
}
