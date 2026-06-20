/**
 * Raw authority-region isolation, shared by the Epic J structural detectors
 * (`ambiguous_authority`, `separator_lookalike`, …). These detectors look for
 * tricks in the parts `parse()` discards, so they work on the prepared raw
 * string rather than the parsed `InspectionContext`.
 *
 * This intentionally mirrors `parse.ts`'s scheme/authority splitting but keeps
 * everything raw — no validation, no normalization — so backslashes, extra
 * slashes, and delimiter look-alikes survive to be inspected.
 */

import { SCHEME_RE, firstIndexOf, isOpaqueScheme, looksLikeHostPort } from "./syntax.js";

export interface AuthorityRegion {
  scheme: string | null;
  /** True for a scheme-relative `//host` (or `\\host`) form with no scheme. */
  protocolRelative: boolean;
  /** Leading run of `/` and `\` that introduced the authority (e.g. `//`, `///`, `/\`). */
  separator: string;
  /** Authority token as written, up to the first ASCII `/` `?` or `#`. */
  authority: string;
  /** Raw path including its leading slashes (may be ""). */
  path: string;
  /** Raw fragment without the leading `#`, or null. */
  fragment: string | null;
  /** True for an opaque scheme with no authority (`javascript:alert(1)`). */
  opaque: boolean;
}

/** Split a prepared input into its raw authority region and surrounding parts. */
export function authorityRegion(prepared: string): AuthorityRegion {
  let scheme: string | null = null;
  let rest = prepared;
  const m = SCHEME_RE.exec(prepared);
  if (m) {
    const candidate = m[1]!.toLowerCase();
    const after = prepared.slice(m[0].length);
    if (!looksLikeHostPort(candidate, after)) {
      scheme = candidate;
      rest = after;
    }
  }

  const protocolRelative = scheme === null && /^[/\\]{2}/.test(prepared);
  const opaque = scheme !== null && isOpaqueScheme(scheme) && !/^[/\\]{2}/.test(rest);

  if (opaque) {
    return { scheme, protocolRelative, separator: "", authority: "", path: rest, fragment: null, opaque };
  }

  let sepEnd = 0;
  while (sepEnd < rest.length && (rest[sepEnd] === "/" || rest[sepEnd] === "\\")) sepEnd++;
  const separator = rest.slice(0, sepEnd);
  const afterSep = rest.slice(sepEnd);

  const delim = firstIndexOf(afterSep, "/?#");
  const authority = delim === -1 ? afterSep : afterSep.slice(0, delim);
  const remainder = delim === -1 ? "" : afterSep.slice(delim);

  let fragment: string | null = null;
  let pathAndQuery = remainder;
  const hashIdx = remainder.indexOf("#");
  if (hashIdx !== -1) {
    fragment = remainder.slice(hashIdx + 1);
    pathAndQuery = remainder.slice(0, hashIdx);
  }
  const qIdx = pathAndQuery.indexOf("?");
  const path = qIdx === -1 ? pathAndQuery : pathAndQuery.slice(0, qIdx);

  return { scheme, protocolRelative, separator, authority, path, fragment, opaque };
}
