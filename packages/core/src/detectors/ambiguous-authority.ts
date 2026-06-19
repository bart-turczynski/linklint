import type { DetectorFinding } from "./types.js";

/**
 * J1 — `ambiguous_authority` (Epic J, FR parser-differential). SCORING.
 *
 * Flags a URL whose authority is structurally ambiguous enough that two parsers
 * would resolve it to different host/port — the Orange Tsai "A New Era of SSRF"
 * class (corroborated by Snyk/Claroty "Exploiting URL Parsing Confusion"). The
 * vulnerability is the *disagreement* between the component that validates a URL
 * and the one that later requests it; linklint's job is to surface that the
 * string is ambiguous, and say which part.
 *
 * Unlike the FR-D-1..12 detectors this runs on the raw, prepared input rather
 * than the parsed `InspectionContext`: most of these payloads are exactly what
 * `parse()` discards (backslash / empty-authority / multi-colon hosts return
 * `null` today, silently losing the signal). Running the scan on the raw string
 * lets an `invalid` result still explain itself, and lets a parseable-but-
 * ambiguous URL keep its resolved verdict plus a scoring reason.
 *
 * Scope (matches the issue): fires ONLY when the input declares itself a URL —
 * an explicit scheme or a protocol-relative `//` form. Bare scheme-less input
 * (`google.com/abc`, `foo bar`) is intentionally out of scope; flagging it would
 * over-trigger on benign typos (SC-2).
 */

// Mirrors parse.ts — a scheme is `name:`; reused here to find the authority.
const SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.\-]*):/;

/** Schemes recognized without a following `//`, so `paypal.com:8080` is not one. */
const KNOWN_SCHEMES = new Set([
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

/** Opaque schemes have no authority to analyze (`javascript:`, `data:`, …). */
const OPAQUE_SCHEMES = new Set([
  "javascript",
  "data",
  "vbscript",
  "blob",
  "mailto",
  "tel",
  "about",
]);

/** Human-readable gloss per sub-signal, for the reason `detail`. */
const SIGNAL_DETAIL: Record<string, string> = {
  multiple_userinfo: "more than one '@' in the authority",
  fragment_in_authority: "a '#@…' tail that the fragment hides from the host parser",
  whitespace_in_authority: "whitespace inside the authority",
  multiple_port: "more than one ':' port separator on the host",
  backslash: "a backslash that browsers fold to '/'",
  slash_confusion: "extra slashes / a network-path reference",
  protocol_relative: "a scheme-relative '//' authority",
};

/**
 * Scan the prepared input for authority ambiguity. Returns a single
 * `ambiguous_authority` finding listing every sub-signal that fired, or `[]`.
 */
export function scanAmbiguousAuthority(prepared: string): DetectorFinding[] {
  if (prepared === "") return [];

  // ── Scheme (same lenient rule as parse.ts) ────────────────────────────────
  let scheme: string | null = null;
  let rest = prepared;
  const m = SCHEME_RE.exec(prepared);
  if (m) {
    const candidate = m[1]!.toLowerCase();
    const after = prepared.slice(m[0].length);
    const looksLikeHostPort =
      (candidate.includes(".") || /^\d+([/?#]|$)/.test(after)) && !KNOWN_SCHEMES.has(candidate);
    if (!looksLikeHostPort) {
      scheme = candidate;
      rest = after;
    }
  }

  const protocolRelative = scheme === null && /^[/\\]{2}/.test(prepared);

  // Gate: only inspect inputs that declare themselves a URL.
  if (scheme === null && !protocolRelative) return [];

  // Opaque schemes carry no authority (unless written with a `//` form).
  if (scheme !== null && OPAQUE_SCHEMES.has(scheme) && !/^[/\\]{2}/.test(rest)) return [];

  // ── Separator: the leading run of '/' and '\' that introduces the authority.
  let sepEnd = 0;
  while (sepEnd < rest.length && (rest[sepEnd] === "/" || rest[sepEnd] === "\\")) sepEnd++;
  const separator = rest.slice(0, sepEnd);
  const afterSep = rest.slice(sepEnd);

  // ── Authority token: up to the first structural '/' '?' or '#'. ───────────
  const delim = firstIndexOf(afterSep, "/?#");
  const authority = delim === -1 ? afterSep : afterSep.slice(0, delim);
  const remainder = delim === -1 ? "" : afterSep.slice(delim);

  // ── Fragment / path from the remainder (for #@ and network-path reference).
  let fragment: string | null = null;
  let pathAndQuery = remainder;
  const hashIdx = remainder.indexOf("#");
  if (hashIdx !== -1) {
    fragment = remainder.slice(hashIdx + 1);
    pathAndQuery = remainder.slice(0, hashIdx);
  }
  const qIdx = pathAndQuery.indexOf("?");
  const path = qIdx === -1 ? pathAndQuery : pathAndQuery.slice(0, qIdx);

  // ── Sub-signals ───────────────────────────────────────────────────────────
  const signals: string[] = [];

  const atCount = countChar(authority, "@");
  if (atCount > 1) signals.push("multiple_userinfo");

  if (fragment !== null && fragment.startsWith("@")) signals.push("fragment_in_authority");

  if (/\s/.test(authority)) signals.push("whitespace_in_authority");

  const hostport = atCount > 0 ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
  if (hasMultiplePort(hostport)) signals.push("multiple_port");

  if (separator.includes("\\") || authority.includes("\\")) signals.push("backslash");

  // 3+ slashes after the scheme (empty authority) or a network-path reference
  // in the path (`http://target.com/////evil.com`, CVE-2021-23435). A plain `//`
  // is left alone — accidental double slashes in paths are common and benign.
  if (separator.length >= 3 || /^\/{3,}/.test(path)) signals.push("slash_confusion");

  if (protocolRelative) signals.push("protocol_relative");

  if (signals.length === 0) return [];

  const glossed = signals.map((s) => `${s} (${SIGNAL_DETAIL[s]})`).join("; ");
  return [
    {
      code: "ambiguous_authority",
      detail: `authority is parser-ambiguous — different URL parsers may resolve a different host: ${glossed}`,
    },
  ];
}

/** Count of `':'` ports on a hostport, ignoring colons inside an IPv6 `[…]`. */
function hasMultiplePort(hostport: string): boolean {
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) return false;
    return countChar(hostport.slice(close + 1), ":") > 1;
  }
  return countChar(hostport, ":") > 1;
}

function countChar(s: string, ch: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s[i] === ch) n++;
  return n;
}

/** Index of the first occurrence of any character in `chars`, or -1. */
function firstIndexOf(s: string, chars: string): number {
  for (let i = 0; i < s.length; i++) {
    if (chars.includes(s[i]!)) return i;
  }
  return -1;
}
