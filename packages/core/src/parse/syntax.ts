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
 * Includes the dangerous opaque schemes FR-D-11 cares about.
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
