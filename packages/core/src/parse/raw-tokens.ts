import { SCHEME_RE, firstIndexOf, isOpaqueScheme, looksLikeHostPort } from "./syntax.js";

/**
 * Validation-free tokenization of a prepared URL candidate. This records the
 * raw syntactic regions linklint cares about before host/IP/PSL validation.
 */
export interface RawUrlTokens {
  /** The prepared input that was tokenized. */
  prepared: string;
  /** Scheme as written, without the trailing colon. */
  rawScheme: string | null;
  /** Lower-cased scheme, without the trailing colon. */
  scheme: string | null;
  /** Present when a scheme-looking prefix was accepted as a scheme. */
  schemeDelimiter: ":" | null;
  /** True for a scheme-relative `//host` (or `\\host`) form with no scheme. */
  protocolRelative: boolean;
  /** True for an opaque scheme with no authority (`javascript:alert(1)`). */
  opaque: boolean;
  /** Raw slash/backslash run that introduced an explicit authority, when present. */
  authorityIntroducer: string;
  /** Authority token as written, before any userinfo/host/port validation. */
  authority: string;
  /** Raw path token without query or fragment. */
  path: string;
  /** Raw query without the leading `?`, or null. */
  query: string | null;
  /** Raw fragment without the leading `#`, or null. */
  fragment: string | null;
}

/**
 * Split a prepared URL candidate into raw tokens without validating the host.
 * Production parsing and structural scans project their existing views from
 * these tokens; validation stays in those projections.
 */
export function tokenizeRawUrl(prepared: string): RawUrlTokens {
  let rawScheme: string | null = null;
  let scheme: string | null = null;
  let schemeDelimiter: ":" | null = null;
  let rest = prepared;

  const m = SCHEME_RE.exec(prepared);
  if (m) {
    const candidateRaw = m[1]!;
    const candidate = candidateRaw.toLowerCase();
    const after = prepared.slice(m[0].length);
    if (!looksLikeHostPort(candidate, after)) {
      rawScheme = candidateRaw;
      scheme = candidate;
      schemeDelimiter = ":";
      rest = after;
    }
  }

  const protocolRelative = scheme === null && /^[/\\]{2}/.test(prepared);
  const opaque = scheme !== null && isOpaqueScheme(scheme) && !/^[/\\]{2}/.test(rest);

  if (opaque) {
    const body = splitPathQueryFragment(rest);
    return {
      prepared,
      rawScheme,
      scheme,
      schemeDelimiter,
      protocolRelative,
      opaque,
      authorityIntroducer: "",
      authority: "",
      ...body,
    };
  }

  if (scheme === "file") {
    const hostless = hostlessFileBody(rest);
    if (hostless !== null) {
      const body = splitPathQueryFragment(hostless.path);
      return {
        prepared,
        rawScheme,
        scheme,
        schemeDelimiter,
        protocolRelative,
        opaque,
        authorityIntroducer: hostless.authorityIntroducer,
        authority: "",
        ...body,
      };
    }
  }

  const authorityIntroducer = leadingAuthorityIntroducer(rest, scheme, protocolRelative);
  const authorityAndRemainder =
    authorityIntroducer === "" ? rest : rest.slice(authorityIntroducer.length);
  const delimIdx = firstIndexOf(authorityAndRemainder, "/?#");
  const authority =
    delimIdx === -1 ? authorityAndRemainder : authorityAndRemainder.slice(0, delimIdx);
  const remainder = delimIdx === -1 ? "" : authorityAndRemainder.slice(delimIdx);

  return {
    prepared,
    rawScheme,
    scheme,
    schemeDelimiter,
    protocolRelative,
    opaque,
    authorityIntroducer,
    authority,
    ...splitPathQueryFragment(remainder),
  };
}

function leadingAuthorityIntroducer(
  rest: string,
  scheme: string | null,
  protocolRelative: boolean,
): string {
  if (scheme === null && !protocolRelative) return "";
  if (!/^[/\\]{2}/.test(rest)) return "";

  let end = 0;
  while (end < rest.length && (rest[end] === "/" || rest[end] === "\\")) end++;
  return rest.slice(0, end);
}

function hostlessFileBody(rest: string): { authorityIntroducer: string; path: string } | null {
  if (rest === "" || rest.startsWith("/") || rest.startsWith("\\")) {
    if (/^[/\\]{2}/.test(rest)) {
      const afterEmptyAuthority = rest.slice(2);
      if (afterEmptyAuthority === "" || afterEmptyAuthority.startsWith("/")) {
        return { authorityIntroducer: rest.slice(0, 2), path: afterEmptyAuthority };
      }
      return null;
    }
    return { authorityIntroducer: "", path: rest };
  }

  return null;
}

function splitPathQueryFragment(input: string): Pick<RawUrlTokens, "path" | "query" | "fragment"> {
  let work = input;
  let fragment: string | null = null;
  let query: string | null = null;

  const hashIdx = work.indexOf("#");
  if (hashIdx !== -1) {
    fragment = work.slice(hashIdx + 1);
    work = work.slice(0, hashIdx);
  }

  const qIdx = work.indexOf("?");
  if (qIdx !== -1) {
    query = work.slice(qIdx + 1);
    work = work.slice(0, qIdx);
  }

  return { path: work, query, fragment };
}
