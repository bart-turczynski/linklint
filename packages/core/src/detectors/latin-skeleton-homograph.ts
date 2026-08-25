import type { Detector, DetectorFinding } from "./types.js";
import { skeleton } from "../unicode/skeleton.js";
import { toUnicode } from "../unicode/idna.js";

/**
 * `homograph_latin_skeleton`. Detects non-ASCII registrable domains whose
 * UTS#39 confusable skeleton is pure ASCII-Latin, and whose non-Latin evidence
 * lies in the registrant-chosen label rather than in the public suffix.
 * Detailed rationale and examples live in docs/reason-codes.md.
 */

/** True when `s` contains any non-ASCII codepoint (i.e. is an IDN/Unicode host). */
function hasNonAscii(s: string): boolean {
  return !/^[\x00-\x7f]*$/.test(s);
}

export const latinSkeletonHomograph: Detector = {
  id: "homograph_latin_skeleton",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const input = ctx.registrableDomain;
    if (!input || ctx.isIp) return [];
    // Canonical Unicode form first: a punycode (xn--) registrable domain is
    // pure ASCII as written, so testing it directly would let the identical host
    // pass simply by being spelled in ACE form. `idn_host` canonicalizes for the
    // same reason. `toUnicode` is total — a malformed ACE label falls back to the
    // ASCII input, fails the non-ASCII guard below, and stays with
    // `punycode_malformed`.
    const host = toUnicode(input.toLowerCase());
    // Non-ASCII host only — a pure-ASCII host is not a cross-script homograph
    // (ASCII digit-folds like g00gle are owned by ascii_homoglyph/brand_homoglyph).
    if (!hasNonAscii(host)) return [];
    // Skip the compatibility-fold family (fullwidth/halfwidth Latin etc.): if the
    // host NFKC-folds to pure ASCII it is owned by idna_mapping_ambiguity.
    if (!hasNonAscii(host.normalize("NFKC"))) return [];
    // The public suffix is not the registrant's to disguise (LINK-ubzfajzm). It
    // is picked from a fixed IANA set, so a non-Latin ccTLD is a fact about the
    // registry rather than a masquerade — yet sixteen ICANN suffixes skeleton to
    // pure ASCII (бг→'6r', срб→'cp6', орг→'opr', рус→'pyc', and ten Norwegian
    // municipal suffixes through æ→ae), which took every host under them,
    // `google.бг` included, to weight-1.0 critical. Require the non-Latin
    // evidence to sit in the label the registrant actually chose.
    //
    // This is only ever a NARROWING: the whole-registrable-domain skeleton test
    // below still has to pass, so no host that is quiet today starts firing.
    // In particular it is NOT per-label evaluation, which LINK-vtfyaizy declined
    // 2-0 on measured evidence — `гора.рф` keeps a non-ASCII skeleton as a whole
    // and stays quiet.
    const suffix = ctx.publicSuffix ? toUnicode(ctx.publicSuffix.toLowerCase()) : "";
    const registrantLabel =
      suffix && host.endsWith(`.${suffix}`) ? host.slice(0, -(suffix.length + 1)) : host;
    if (!hasNonAscii(registrantLabel)) return [];

    const skel = skeleton(host);
    // Fire only when the confusable skeleton is ENTIRELY ASCII — every character
    // folded to a Latin look-alike. A genuine non-Latin word retains a non-ASCII
    // codepoint here and is left alone.
    if (hasNonAscii(skel)) return [];

    // Name the domain by what was written, adding the decoded form when the input
    // was punycode — otherwise the detail would read as an all-ASCII `xn--` host.
    const shown =
      host === input.toLowerCase() ? `'${input}'` : `'${input}' (Unicode form '${host}')`;

    return [
      {
        code: "homograph_latin_skeleton",
        detail:
          `registrable domain ${shown} is non-Latin but its UTS#39 confusable ` +
          `skeleton is pure ASCII-Latin ('${skel.normalize("NFC")}') — a whole-label ` +
          "homograph masquerading as an ASCII domain",
      },
    ];
  },
};
