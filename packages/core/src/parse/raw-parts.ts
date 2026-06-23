import { stripInvisible } from "../unicode/format-chars.js";
import { analyzeIpv6 } from "./ip.js";
import { SCHEME_RE, firstIndexOf, isOpaqueScheme, looksLikeHostPort } from "./syntax.js";

const ILLEGAL_HOST_RE = /[\s<>"{}|\\^`]/;
const HOST_CHARS_RE = /^[\p{L}\p{M}\p{N}._%\-]+$/u;

/**
 * The raw, "what was written" view of an input: the components recovered by
 * syntax parsing, before any host facts (IP/PSL/IDNA) are derived. Values are
 * preserved verbatim so character-level detectors can inspect them.
 */
export interface RawParts {
  scheme: string | null;
  userinfo: string | null;
  rawHost: string;
  port: number | null;
  path: string;
  query: string | null;
  fragment: string | null;
}

/**
 * Parse a prepared input string into raw URL components. Returns `null` when no
 * useful URL/host can be identified — the caller turns that into a
 * `status: "invalid"` result (never throws). See FR-IN-1..4 and architecture
 * §4.1. Expects the output of `prepare()` (non-empty); callers handle `""`.
 */
export function parseRawParts(prepared: string): RawParts | null {
  // ── Scheme ────────────────────────────────────────────────────────────────
  let scheme: string | null = null;
  let rest = prepared;
  const m = SCHEME_RE.exec(prepared);
  if (m) {
    const candidate = m[1]!.toLowerCase();
    const after = prepared.slice(m[0].length);
    if (looksLikeHostPort(candidate, after)) {
      // e.g. "paypal.com:8080" or "localhost:8080" — missing scheme, not opaque.
      scheme = null;
      rest = prepared;
    } else {
      scheme = candidate;
      rest = after;
    }
  }

  // ── Opaque scheme (no authority): javascript:, data:, mailto:, … ───────────
  if (scheme && isOpaqueScheme(scheme) && !rest.startsWith("//")) {
    return {
      scheme,
      userinfo: null,
      rawHost: "",
      port: null,
      path: rest,
      query: null,
      fragment: null,
    };
  }

  // ── Local file: forms (hostless) ────────────────────────────────────────────
  // `file:` URLs may name a local path with no authority. The WHATWG-canonical
  // local shapes are `file:/etc/passwd` (single slash, no authority) and
  // `file:///etc/passwd` (explicit empty authority). Both denote host = none +
  // path. The generic authority logic below would reject these — `file:/…` lands
  // an empty authority that fails hostIsValid (parse_error), and `file:///…`'s
  // `///` trips the structural ambiguous_authority scan to `invalid` — so the
  // dangerous_scheme detector (which keys off scheme === "file") never runs.
  // That is a real bypass: a sanitizer that only blocks `file://host/…` lets the
  // hostless local forms through (the changedetection.io local-file-read class).
  // Scoped strictly to `file:` so no other scheme's invalid-input contract moves.
  // `file://host/…` still has a non-empty authority and falls through to the
  // normal path below, keeping its existing host parse.
  if (scheme === "file") {
    // Strip an optional leading `//` authority introducer, then any remaining
    // leading slashes. A non-empty authority (e.g. `file://localhost/…`) is left
    // for the generic branch; only the hostless local forms are special-cased.
    const afterSlashes = rest.startsWith("//") ? rest.slice(2) : rest;
    if (afterSlashes === "" || afterSlashes.startsWith("/")) {
      // Hostless: everything after the scheme (minus the empty authority) is the
      // path. Preserve a single leading slash so the path reads `/etc/passwd`.
      const localPath = afterSlashes === "" ? rest : "/" + afterSlashes.replace(/^\/+/, "");
      let work = localPath;
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
      return { scheme, userinfo: null, rawHost: "", port: null, path: work, query, fragment };
    }
  }

  // ── Authority + path/query/fragment ─────────────────────────────────────────
  let authorityAndRest: string;
  if (scheme && rest.startsWith("//")) {
    authorityAndRest = rest.slice(2);
  } else if (scheme && !rest.startsWith("//")) {
    // Non-opaque scheme with no `//` (e.g. "http:example.com") — be lenient.
    authorityAndRest = rest;
  } else {
    // Missing scheme: treat the whole thing as authority + path.
    authorityAndRest = rest;
  }

  const delimIdx = firstIndexOf(authorityAndRest, "/?#");
  const authority = delimIdx === -1 ? authorityAndRest : authorityAndRest.slice(0, delimIdx);
  const remainder = delimIdx === -1 ? "" : authorityAndRest.slice(delimIdx);

  // userinfo (split at LAST '@', per WHATWG)
  let userinfo: string | null = null;
  let hostport = authority;
  const atIdx = authority.lastIndexOf("@");
  if (atIdx !== -1) {
    userinfo = authority.slice(0, atIdx);
    hostport = authority.slice(atIdx + 1);
  }

  // host + port
  let rawHost: string;
  let port: number | null = null;
  let bracketed = false;
  if (hostport.startsWith("[")) {
    bracketed = true;
    const close = hostport.indexOf("]");
    if (close === -1) return null;
    rawHost = hostport.slice(1, close);
    const portPart = hostport.slice(close + 1);
    if (portPart.startsWith(":")) {
      const p = portPart.slice(1);
      if (!/^\d+$/.test(p)) return null;
      port = Number(p);
    } else if (portPart !== "") {
      return null;
    }
  } else {
    const colon = hostport.lastIndexOf(":");
    if (colon !== -1 && /^\d+$/.test(hostport.slice(colon + 1))) {
      port = Number(hostport.slice(colon + 1));
      rawHost = hostport.slice(0, colon);
    } else {
      rawHost = hostport;
    }
  }

  // A bracketed host must be a valid IPv6 literal; an unbracketed one a reg-name
  // or IPv4. (Brackets carry the colons that hostIsValid would otherwise reject.)
  if (bracketed) {
    if (analyzeIpv6(rawHost) === null) return null;
  } else if (!hostIsValid(rawHost)) {
    return null;
  }

  // path / query / fragment
  let path = "";
  let query: string | null = null;
  let fragment: string | null = null;
  if (remainder !== "") {
    let work = remainder;
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
    path = work;
  }

  return { scheme, userinfo, rawHost, port, path, query, fragment };
}

/**
 * A host is valid if, after removing invisible/format characters, it is a
 * non-empty reg-name (unicode letters/marks/numbers, dot, hyphen, underscore,
 * percent) or an IP-ish literal — and has no whitespace or structural junk.
 * Invisible characters are deliberately tolerated here so detectors can flag
 * them rather than the input being rejected as unparseable.
 */
function hostIsValid(rawHost: string): boolean {
  const clean = stripInvisible(rawHost);
  if (clean === "") return false;
  if (ILLEGAL_HOST_RE.test(clean)) return false;
  if (!HOST_CHARS_RE.test(clean)) return false;
  const labels = clean.replace(/\.$/, "").split(".");
  if (labels.some((l) => l === "")) return false;
  return true;
}
