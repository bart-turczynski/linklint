import type { DetectorFinding } from "./types.js";
import { authorityRegion, type AuthorityRegion } from "../parse/authority-region.js";

/**
 * `ambiguous_authority` (FR parser-differential). SCORING.
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
export function scanAmbiguousAuthority(
  prepared: string,
  region: AuthorityRegion = authorityRegion(prepared),
): DetectorFinding[] {
  if (prepared === "") return [];


  // Gate: only inspect inputs that declare themselves a URL with an authority.
  if (region.opaque) return [];
  if (region.scheme === null && !region.protocolRelative) return [];

  const { separator, authority, path, fragment, protocolRelative } = region;

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
