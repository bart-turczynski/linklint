import type { ParsedUrl } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import { stripInvisible } from "../unicode/format-chars.js";
import { toUnicode } from "../unicode/idna.js";
import { analyzeHost, type PslResult } from "./psl.js";
import { analyzeIpv4, analyzeIpv6 } from "./ip.js";
import { prepare } from "./prepare.js";
import { SCHEME_RE, firstIndexOf, isOpaqueScheme, looksLikeHostPort } from "./syntax.js";
import { normalizeOptions, type RuntimeConfig } from "./runtime.js";

const ILLEGAL_HOST_RE = /[\s<>"{}|\\^`]/;
const HOST_CHARS_RE = /^[\p{L}\p{M}\p{N}._%\-]+$/u;

/**
 * Parse an arbitrary string into canonical components, preserving raw values for
 * character-level detectors. Returns `null` when no useful URL/host can be
 * identified — the caller turns that into a `status: "invalid"` result (never
 * throws). See FR-IN-1..4 and architecture §4.1.
 */
export function parse(
  input: string,
  runtime: RuntimeConfig = normalizeOptions({}),
): InspectionContext | null {
  const prepared = prepare(input);
  if (prepared === "") return null;

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
    return buildContext(
      input,
      {
        scheme,
        userinfo: null,
        rawHost: "",
        port: null,
        path: rest,
        query: null,
        fragment: null,
      },
      runtime,
    );
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

  return buildContext(
    input,
    { scheme, userinfo, rawHost, port, path, query, fragment },
    runtime,
  );
}

interface RawParts {
  scheme: string | null;
  userinfo: string | null;
  rawHost: string;
  port: number | null;
  path: string;
  query: string | null;
  fragment: string | null;
}

function buildContext(input: string, raw: RawParts, runtime: RuntimeConfig): InspectionContext {
  const host = stripInvisible(raw.rawHost);
  // An IP host (IPv4 canonical/obfuscated, or an IPv6 literal) is never a
  // registrable domain — null the PSL fields so domain-based detectors
  // (embedded_domain, risky_tld) skip it. IPs also have no Unicode/IDN form.
  const isIpv4 = host !== "" && analyzeIpv4(host) !== null;
  const isIp = isIpv4 || (host !== "" && host.includes(":") && analyzeIpv6(host) !== null);
  const psl: PslResult = host === "" || isIp ? emptyPsl(isIp) : analyzeHost(host);
  const hostUnicode = host === "" || isIp ? host : toUnicode(host);
  const hostLabels =
    host === "" ? [] : isIp && host.includes(":") ? [host] : host.replace(/\.$/, "").split(".");

  const parsed: ParsedUrl = {
    scheme: raw.scheme,
    userinfo: raw.userinfo,
    effectiveHost: host === "" ? null : host,
    registrableDomain: psl.registrableDomain,
    publicSuffix: psl.publicSuffix,
    subdomain: psl.subdomain,
    hostLabels,
    port: raw.port,
    path: raw.path,
    query: raw.query,
    fragment: raw.fragment,
    isIp: psl.isIp,
  };

  return {
    input,
    scheme: raw.scheme,
    userinfo: raw.userinfo,
    rawHost: raw.rawHost,
    host,
    hostUnicode,
    isIp: psl.isIp,
    hostLabels,
    registrableDomain: psl.registrableDomain,
    publicSuffix: psl.publicSuffix,
    subdomain: psl.subdomain,
    port: raw.port,
    path: raw.path,
    query: raw.query,
    fragment: raw.fragment,
    parsed,
    runtime,
  };
}

function emptyPsl(isIp = false): PslResult {
  return { registrableDomain: null, publicSuffix: null, subdomain: null, isIp };
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
