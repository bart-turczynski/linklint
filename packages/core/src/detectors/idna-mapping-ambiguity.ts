import type { DetectorFinding } from "./types.js";
import { authorityRegion, type AuthorityRegion } from "../parse/authority-region.js";
import { toAsciiUnder } from "../unicode/idna.js";

/**
 * J9 — `idna_mapping_ambiguity` (Epic J). Informational (weight 0) for now.
 *
 * Flags the Tsai "Abusing IDNA Standard" class: a host whose characters are
 * mapped *differently by different IDNA standards*, so the component that
 * validates the URL and the one that later resolves it reach different domains.
 * Distinct from `confusable_char` (visual similarity) — this is about RESOLVER
 * DISAGREEMENT, detected by running the host through both standards.
 *
 *   - Group A — deviation characters (ß, ς, ZWJ, ZWNJ): IDNA2003 maps them
 *     (ß→ss) while UTS-46/IDNA2008 keeps/encodes them, so the two ASCII forms
 *     differ. `wordpreß.com` → `wordpress.com` (IDNA2003) vs `xn--wordpre-6va.com`.
 *   - Group B — compatibility folds (fullwidth / circled Latin): both standards
 *     fold them to plain ASCII with no punycode, so a parser that does NOT apply
 *     IDNA mapping reads a different host than the browser. `ｇｏｏｇｌｅ.com` and
 *     `ⓖⓞⓞⓖⓛⓔ.com` → `google.com`.
 *
 * Runs as a raw scan (like J1/J2) rather than a context detector: circled
 * letters and other compatibility characters are rejected by `parse()`'s
 * host-character rule, so a context detector would never see them. Scanning the
 * raw authority lets an `invalid` result carry the explanation, and a parseable
 * host keep its verdict plus the annotation.
 *
 * Weight: informational (0). A lone ß is a legitimate German IDN (`baß.de` is a
 * real registrable domain), so the base signal must not raise severity (SC-2).
 * Epic G wires the SCORING escalation: when the alternate IDNA2003 mapping equals
 * a known brand (`wordpreß` → `wordpress`), it becomes an impersonation signal.
 * Decision recorded against the brainstorm's OQ-J9b.
 *
 * Implemented with the vetted `tr46` library in both processing modes
 * (FR-LIB-1: do not hand-roll IDNA).
 */
export function scanIdnaMappingAmbiguity(
  prepared: string,
  region: AuthorityRegion = authorityRegion(prepared),
): DetectorFinding[] {
  if (prepared === "") return [];

  const { authority, opaque } = region;
  if (opaque || authority === "") return [];

  const host = hostFromAuthority(authority);
  // Only non-ASCII hosts can have an IDNA mapping ambiguity; this also skips IPs
  // and userinfo-only authorities, which are pure ASCII.
  if (host === "" || isPureAscii(host)) return [];

  const ace2008 = toAsciiUnder(host, false); // UTS-46 / IDNA2008
  const ace2003 = toAsciiUnder(host, true); // IDNA2003 (transitional)

  // Group A — the two standards resolve to different ASCII domains.
  if (ace2008 !== null && ace2003 !== null && ace2008 !== ace2003) {
    return [
      {
        code: "idna_mapping_ambiguity",
        detail:
          `host resolves to different domains across IDNA standards: '${ace2003}' under ` +
          `IDNA2003 vs '${ace2008}' under UTS-46/IDNA2008 — a validator and a requester ` +
          "using different standards reach different sites",
      },
    ];
  }

  // Group A (continued) — accepted by IDNA2003 but rejected by UTS-46.
  if (ace2003 !== null && ace2008 === null) {
    return [
      {
        code: "idna_mapping_ambiguity",
        detail:
          `host is accepted by IDNA2003 (resolving to '${ace2003}') but rejected by ` +
          "UTS-46/IDNA2008 — parsers disagree on whether it is even valid",
      },
    ];
  }

  // Group B — non-ASCII characters fold entirely to ASCII (no punycode), so a
  // non-normalizing validator sees a different string than the resolver.
  if (ace2008 !== null && isPureAscii(ace2008) && !/(^|\.)xn--/i.test(ace2008)) {
    return [
      {
        code: "idna_mapping_ambiguity",
        detail:
          `host's non-ASCII characters map to the ASCII domain '${ace2008}' under IDNA — a ` +
          "parser that does not apply IDNA mapping would read a different host",
      },
    ];
  }

  return [];
}

/** Extract the host from a raw authority token (`user@host:port`, `[v6]:port`). */
function hostFromAuthority(authority: string): string {
  let hostport = authority;
  const at = hostport.lastIndexOf("@");
  if (at !== -1) hostport = hostport.slice(at + 1);
  if (hostport.startsWith("[")) return ""; // IPv6 literal — never an IDN
  const colon = hostport.lastIndexOf(":");
  if (colon !== -1 && /^\d+$/.test(hostport.slice(colon + 1))) {
    hostport = hostport.slice(0, colon);
  }
  return hostport;
}

/** True if every code unit of `s` is in the ASCII range (U+0000–U+007F). */
function isPureAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}
