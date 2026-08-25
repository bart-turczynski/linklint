/**
 * Shared parser syntax primitives used by both the validating parser
 * (`parse.ts`) and the raw authority-region isolator (`authority-region.ts`).
 *
 * These two modules deliberately apply the same scheme/authority splitting
 * rules — one normalizing, one keeping everything raw — so the scheme regex,
 * scheme sets, and low-level helpers must stay identical. Centralizing them
 * here removes the drift risk of maintaining two hand-kept copies.
 */

export const SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.\-]*):/;

/**
 * Schemes that linklint recognizes even without a following `//` authority, so
 * that a missing-scheme bare host (`paypal.com:8080`) is not mistaken for one.
 * Includes the dangerous opaque schemes FR-D-11 cares about — `javascript`,
 * `data`, `vbscript`, `blob` and `file`, matching `DANGEROUS_SCHEMES` in
 * `detectors/dangerous-scheme.ts`.
 *
 * That "includes" is a superset claim and holds, but on its own it explains
 * only five of the entries, which has already been misread as an assertion that
 * every member is opaque or dangerous (LINK-iuzphbnp). It is not. Membership
 * has exactly one effect: `looksLikeHostPort` below. A `scheme:` prefix whose
 * tail is digits, or whose token contains a dot, is otherwise read as a bare
 * `host:port`, so `view-source:8080` and `chrome:8080` are scheme-and-body only
 * because these names are listed here — drop `view-source` and that input
 * becomes host `view-source` on port 8080, a different verdict.
 *
 * `view-source` therefore is NOT a dead entry, and it is also not a promise
 * that linklint unwraps the nested scheme Chrome reads there. It does not:
 * `view-source:https://example.com/` leaves `https:` as the authority region,
 * which is not a host, so the input is `invalid` and fails closed. What it now
 * gets is a `parse_error` that says so (see `failure.ts`). Unwrapping would
 * move verdicts and is a separate question from naming the failure.
 */
export const KNOWN_SCHEMES = new Set([
  "http",
  "https",
  "ftp",
  "ftps",
  "ws",
  "wss",
  "file",
  "mailto",
  "tel",
  "about",
  "chrome",
  "view-source",
  "javascript",
  "data",
  "vbscript",
  "blob",
]);

/** Schemes whose body is opaque (no host/authority to parse). */
export const OPAQUE_SCHEMES = new Set([
  "javascript",
  "data",
  "vbscript",
  "blob",
  "mailto",
  "tel",
  "about",
]);

/** Whether `candidate` is a scheme linklint recognizes without a `//` authority. */
export function isKnownScheme(candidate: string): boolean {
  return KNOWN_SCHEMES.has(candidate);
}

/** Whether `candidate` is an opaque scheme with no authority to parse. */
export function isOpaqueScheme(candidate: string): boolean {
  return OPAQUE_SCHEMES.has(candidate);
}

/**
 * Whether a `scheme:`-looking prefix is really a missing-scheme bare host:port
 * (e.g. `paypal.com:8080` or `localhost:8080`) rather than an actual scheme.
 * `candidate` is the lowercased scheme token; `after` is the text following the
 * colon.
 */
export function looksLikeHostPort(candidate: string, after: string): boolean {
  return (
    (candidate.includes(".") || /^\d+([/?#]|$)/.test(after)) && !KNOWN_SCHEMES.has(candidate)
  );
}

/** Index of the first occurrence of any character in `chars`, or -1. */
export function firstIndexOf(s: string, chars: string): number {
  for (let i = 0; i < s.length; i++) {
    if (chars.includes(s[i]!)) return i;
  }
  return -1;
}
