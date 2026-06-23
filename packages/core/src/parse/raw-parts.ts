import { stripInvisible } from "../unicode/format-chars.js";
import { analyzeIpv6 } from "./ip.js";
import { tokenizeRawUrl, type RawUrlTokens } from "./raw-tokens.js";

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
export function parseRawParts(
  prepared: string,
  tokens: RawUrlTokens = tokenizeRawUrl(prepared),
): RawParts | null {
  const { scheme } = tokens;

  // ── Opaque scheme (no authority): javascript:, data:, mailto:, … ───────────
  if (tokens.opaque) {
    return {
      scheme,
      userinfo: null,
      rawHost: "",
      port: null,
      path: opaqueBody(tokens),
      query: null,
      fragment: null,
    };
  }

  // ── Local file: forms (hostless) ───────────────────────────────────────────
  // The raw tokenizer owns the `file:/path` and `file:///path` split. Keep this
  // projection hostless so dangerous-scheme policy still sees local file URLs.
  if (scheme === "file" && tokens.authority === "") {
    return {
      scheme,
      userinfo: null,
      rawHost: "",
      port: null,
      path: tokens.path,
      query: tokens.query,
      fragment: tokens.fragment,
    };
  }

  if (!hasParseableAuthorityIntroducer(tokens)) return null;

  // ── Authority + path/query/fragment ─────────────────────────────────────────
  // userinfo (split at LAST '@', per WHATWG)
  let userinfo: string | null = null;
  let hostport = tokens.authority;
  const atIdx = tokens.authority.lastIndexOf("@");
  if (atIdx !== -1) {
    userinfo = tokens.authority.slice(0, atIdx);
    hostport = tokens.authority.slice(atIdx + 1);
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

  return {
    scheme,
    userinfo,
    rawHost,
    port,
    path: tokens.path,
    query: tokens.query,
    fragment: tokens.fragment,
  };
}

function hasParseableAuthorityIntroducer(tokens: RawUrlTokens): boolean {
  if (tokens.scheme === null) {
    // Historically, scheme-less `//host` is scanned structurally but does not
    // parse as a valid host input.
    return !tokens.protocolRelative;
  }

  // `scheme://host` is the only explicit authority introducer accepted by the
  // parser. Extra slashes and backslashes stay lexical-only findings.
  return tokens.authorityIntroducer === "" || tokens.authorityIntroducer === "//";
}

function opaqueBody(tokens: RawUrlTokens): string {
  let body = tokens.path;
  if (tokens.query !== null) body += `?${tokens.query}`;
  if (tokens.fragment !== null) body += `#${tokens.fragment}`;
  return body;
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
