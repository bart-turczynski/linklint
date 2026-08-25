import type { DetectorFinding } from "./types.js";
import { authorityRegion, type AuthorityRegion } from "../parse/authority-region.js";

/**
 * `ambiguous_authority` (FR parser-differential). SCORING.
 *
 * Flags a URL whose authority is read differently by two conforming readers —
 * the Orange Tsai "A New Era of SSRF" class (corroborated by Snyk/Claroty
 * "Exploiting URL Parsing Confusion"). The vulnerability is the *disagreement*
 * between the component that validates a URL and the one that later requests
 * it; linklint's job is to surface that the string is ambiguous, and say which
 * part.
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
 *
 * ---------------------------------------------------------------------------
 * THE READER LEDGER (LINK-ouljoseh). READ THIS BEFORE ADDING A SUB-SIGNAL.
 * ---------------------------------------------------------------------------
 *
 * `docs/architecture.md` §1.1 form 2 is DESTINATION-scoped: "two conforming
 * readers resolve the same string to DIFFERENT DESTINATIONS". §6 says the same
 * thing from the other end: "the discriminator is *disagreement between
 * standards*, not exotic input". A sub-signal that cannot NAME two readers that
 * disagree about where the string goes does not belong here, however exotic the
 * string looks.
 *
 * The bar, therefore, and it is not negotiable: **every sub-signal below states
 * a NAMED PAIR of real readers and the destination each one reaches.** Four
 * shapes shipped here without one and were removed or downgraded once the pairs
 * were actually measured. Adding a sub-signal without the pair is how that
 * happens again.
 *
 * Readers used, all run against the payload on 2026-08-25:
 *   WHATWG `new URL(u).host` (Node 26) · Node legacy `url.parse(u).host` ·
 *   Python `urllib.parse.urlsplit(u)` · Go `net/url.Parse(u)` ·
 *   PHP `parse_url(u)` · Java `new URI(u).getHost()` (OpenJDK 21) ·
 *   Java `new URL(u).getHost()` (OpenJDK 21).
 *
 * SHIPPING — different host, two named readers (the `DIFFERENT_HOST` set):
 *
 *   `backslash`               `http://good.com\@evil.com/`
 *                             WHATWG `new URL` -> `good.com` (§4.4 folds `\`
 *                             to `/`, so `@evil.com/` is path)
 *                             Python `urlsplit` -> `evil.com` (RFC 3986 keeps
 *                             `\` in userinfo, so the last `@` wins)
 *                             Two accepting readers, two hosts. Go and Java
 *                             reject; PHP agrees with Python.
 *
 *   `whitespace_in_authority` `http://127.0.0.1 foo.google.com/`
 *                             Node legacy `url.parse` -> `127.0.0.1`
 *                             Python `urlsplit` -> `127.0.0.1 foo.google.com`
 *                             Two accepting readers, two hosts; PHP agrees with
 *                             Python. This is Tsai's glibc-NSS shape — the
 *                             validator sees one host, the resolver dials the
 *                             other.
 *
 *   `slash_confusion`         `https:///evil.com` (EMPTY AUTHORITY ONLY)
 *                             WHATWG `new URL` -> `evil.com` (special schemes
 *                             skip empty path segments)
 *                             Go `net/url` -> Host `""`, Path `/evil.com`
 *                             Both accept; one dials `evil.com` and one dials
 *                             nothing. Python and Node legacy agree with Go.
 *                             Caveat, measured: on a NON-special scheme
 *                             (`foo://///////bar.com/`) WHATWG also yields an
 *                             empty host, so that sub-case is accept-vs-reject
 *                             (PHP refuses) rather than different-host.
 *
 * SHIPPING — accept-vs-reject only, NOT different-host (`ACCEPT_VS_REJECT`):
 *
 *   `multiple_userinfo`       `http://foo@evil.com:80@google.com/`
 *                             WHATWG / Node legacy / Python / Go / PHP ->
 *                             `google.com`; Java `URI.getHost()` -> `null`,
 *                             Java `URL.getHost()` -> `""`.
 *                             NO reader reaches `evil.com`. The disagreement is
 *                             real and is between standards — the WHATWG URL
 *                             Standard specifies the LAST `@` as the boundary,
 *                             RFC 3986 §3.2.1 excludes `@` from userinfo and so
 *                             declares the authority non-conforming — but it is
 *                             a fork between "this host" and "no host", which is
 *                             what §1.1 grades via `ambiguous_numeric_host`
 *                             ("one reader refusing what another dials"). Kept
 *                             for that reason, with the different-host claim
 *                             removed from the detail.
 *
 *   `multiple_port`           `http://127.0.0.1:11211:80/`
 *                             WHATWG / Node legacy / Go / Java `URL` REJECT;
 *                             Python `urlsplit` -> `127.0.0.1` (`.port` raises);
 *                             PHP `parse_url` -> host `127.0.0.1:11211`;
 *                             Java `URI` -> `null`.
 *                             NO reader reaches a different machine or a
 *                             different port. Weaker still than the row above —
 *                             both standards call it non-conforming and the
 *                             accepting readers are simply lenient — but it is
 *                             the named explanation that keeps
 *                             `http://127.0.0.1:11211:80/` from collapsing to a
 *                             bare `parse_error`, which §1.1's fourth rule asks
 *                             it not to do. Kept, detail corrected.
 *
 * REMOVED — measured, no disagreement at all:
 *
 *   `protocol_relative`       `//www.example.com/a.js`
 *                             Python / Go / PHP / Java `URI` -> `www.example.com`;
 *                             WHATWG resolves it against its base to the same
 *                             host. Scheme inheritance is RFC 3986 §4.2 BY
 *                             DESIGN. It is also the highest-volume shape on the
 *                             web (every protocol-relative asset tag). Deleted.
 *
 *   `slash_confusion` (path)  `http://target.com/////evil.com`
 *                             ALL SEVEN readers -> `target.com`, path
 *                             `/////evil.com`. The `/^\/{3,}/` path branch was
 *                             the one shipping CRITICAL and it never had a pair.
 *                             Deleted; the empty-authority branch stays.
 *
 *   `fragment_in_authority`   `http://google.com#@evil.com/`
 *                             ALL SEVEN readers -> `google.com`. `#` opens the
 *                             fragment for every one of them and the `@` after
 *                             it is fragment text. Deleted.
 *                             KNOWN GAP, recorded rather than papered over: the
 *                             Log4j-class payload this branch was introduced for
 *                             — `ldap://exampleldap.com#.evilhost.com/a`, which
 *                             has no `@` at all — never matched the branch and
 *                             is still not detected. Removing the branch removes
 *                             a false claim; it does not lose a working check.
 */

/** Human-readable gloss per sub-signal, for the reason `detail`. */
const SIGNAL_DETAIL: Record<string, string> = {
  multiple_userinfo: "more than one '@' in the authority",
  whitespace_in_authority: "whitespace inside the authority",
  multiple_port: "more than one ':' port separator on the host",
  backslash: "a backslash that browsers fold to '/'",
  slash_confusion: "3+ slashes after the scheme, i.e. an empty authority",
};

/**
 * Sub-signals backed by a named pair of readers reaching DIFFERENT hosts. See
 * the ledger above; each entry there names its pair and both destinations.
 */
const DIFFERENT_HOST: ReadonlySet<string> = new Set([
  "backslash",
  "whitespace_in_authority",
  "slash_confusion",
]);

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

  // `path` and `fragment` are deliberately NOT read: the two sub-signals that
  // consumed them (`slash_confusion`'s path branch, `fragment_in_authority`)
  // both asserted a disagreement no reader has. See the ledger above.
  const { separator, authority } = region;

  const signals: string[] = [];

  const atCount = countChar(authority, "@");
  if (atCount > 1) signals.push("multiple_userinfo");

  if (/\s/.test(authority)) signals.push("whitespace_in_authority");

  const hostport = atCount > 0 ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
  if (hasMultiplePort(hostport)) signals.push("multiple_port");

  if (separator.includes("\\") || authority.includes("\\")) signals.push("backslash");

  // 3+ slashes after the scheme, i.e. an EMPTY authority: WHATWG dials the
  // first path segment as the host while Go, Python and Node's legacy parser
  // dial nothing. The path branch this condition used to carry
  // (`/^\/{3,}/.test(path)`, `http://target.com/////evil.com`) is gone — all
  // seven readers resolve `target.com` there, so it asserted a disagreement
  // that does not exist. See the ledger above.
  if (separator.length >= 3) signals.push("slash_confusion");

  if (signals.length === 0) return [];

  return [
    {
      code: "ambiguous_authority",
      detail: `authority is parser-ambiguous — ${describe(signals)}`,
    },
  ];
}

/**
 * Build the `detail` clause. Sub-signals are described by what they actually
 * prove: a different-host fork, or a fork between resolving and refusing. The
 * shipped blanket sentence ("different URL parsers may resolve a different
 * host") was attached to every sub-signal and was false for four of them.
 */
function describe(signals: string[]): string {
  const gloss = (s: string): string => `${s} (${SIGNAL_DETAIL[s]})`;
  const differentHost = signals.filter((s) => DIFFERENT_HOST.has(s));
  const acceptVsReject = signals.filter((s) => !DIFFERENT_HOST.has(s));

  const clauses: string[] = [];
  if (differentHost.length > 0) {
    clauses.push(
      `two conforming readers resolve a different host: ${differentHost.map(gloss).join("; ")}`,
    );
  }
  if (acceptVsReject.length > 0) {
    clauses.push(
      "readers disagree on whether the string is a usable URL at all — one resolves a host, " +
        `another refuses it, and none reaches a different host: ${acceptVsReject.map(gloss).join("; ")}`,
    );
  }
  return clauses.join(" — and separately, ");
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
