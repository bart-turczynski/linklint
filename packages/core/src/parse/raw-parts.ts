import { stripInvisible } from "../unicode/format-chars.js";
import { analyzeIpv6 } from "./ip.js";
import { tokenizeRawUrl, type RawUrlTokens } from "./raw-tokens.js";

const ILLEGAL_HOST_RE = /[\s<>"{}|\\^`]/;
const HOST_CHARS_RE = /^[\p{L}\p{M}\p{N}._%\-]+$/u;

/**
 * What makes the tail after a `:` a *port claim* at all. Anything else is not a
 * malformed port, it is simply not a port — `example.com:abc` is a bad host.
 */
const PORT_DIGITS_RE = /^\d+$/;

/**
 * Inclusive upper bound for a decimal URL port (LINK-drucugmm).
 *
 * **Range decision: `0`–`65535`, matching WHATWG exactly.** WHATWG's URL parser
 * accumulates the port digits and reports a *validation failure* — the URL does
 * not parse at all — as soon as the value exceeds 2^16-1, so
 * `new URL("http://example.com:65536/")` throws. It does, however, accept port
 * `0`: `new URL("http://example.com:0/").port === "0"`.
 *
 * **Why `0` stays valid.** It is syntactically legal, and this is a syntax
 * parser. "No host answers on port 0" is a transport fact, not a parse fact,
 * and linklint never connects from the offline core, so it has no standing to
 * be stricter than its stated consumer semantics — rejecting `:0` would make
 * linklint disagree with every WHATWG parser on an input they all accept, which
 * is the exact class of disagreement this fix exists to remove. (An *observed
 * socket peer* port of 0 is a different question and is bounded `1`–`65535`
 * elsewhere in the online package: a peer that reports port 0 is meaningless,
 * whereas a URL that writes port 0 merely names a port nothing listens on.)
 *
 * Leading zeros follow WHATWG too — it strips them before bounding, and
 * `Number()` on a digits-only string does the same — so `:0000080` is port 80
 * and `:065536` is out of range. The comparison is never a float-precision
 * guess: any digit string worth ≤ 65535 has at most five significant digits and
 * is exactly representable, and a 400-digit string converts to `Infinity`,
 * which fails the bound rather than sneaking through. (Before this bound,
 * `:999…9` produced `port: Infinity`, which `JSON.stringify` renders as `null`
 * — indistinguishable from "no port" to every downstream consumer.)
 *
 * An out-of-range port is never clamped or wrapped: reporting `65535` for an
 * input that wrote `999999` would attribute a port the input never named. The
 * whole authority is unparseable instead, which routes to `status: "invalid"`
 * with the existing `parse_error` reason. Raw-port evidence survives in the
 * verbatim `input` echo, which `inspect()` preserves on the invalid path.
 */
const MAX_PORT = 65535;

/**
 * Convert a port claim to its numeric value, or `null` when it is out of range.
 * Precondition: `digits` has already matched {@link PORT_DIGITS_RE}, so the
 * lower bound of 0 is structurally unreachable and only the ceiling is checked.
 */
function toPort(digits: string): number | null {
  const value = Number(digits);
  return value > MAX_PORT ? null : value;
}

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
      if (!PORT_DIGITS_RE.test(p)) return null;
      // Out of range is unparseable, exactly as for the unbracketed form below —
      // `[::1]:99999` is no more a URL than `example.com:99999` (MAX_PORT).
      port = toPort(p);
      if (port === null) return null;
    } else if (portPart !== "") {
      return null;
    }
  } else {
    const colon = hostport.lastIndexOf(":");
    if (colon !== -1 && PORT_DIGITS_RE.test(hostport.slice(colon + 1))) {
      // The tail IS a port claim, so an out-of-range value makes the whole
      // authority unparseable. Falling through to `rawHost = hostport` would
      // reach the same `null` via hostIsValid (a colon is not a host character),
      // but only by accident — say it here (MAX_PORT).
      port = toPort(hostport.slice(colon + 1));
      if (port === null) return null;
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
