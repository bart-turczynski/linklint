import type { Detector, DetectorFinding } from "./types.js";
import { analyzeIpv4, stripTrailingRootDot } from "../parse/ip.js";

/**
 * FR-D-7b — ambiguous numeric host (P3 / LINK-slcjsjcs). Scoring, pure lexical,
 * NO second parser.
 *
 * Catches the malformed-IPv4-shaped hosts that different URL readers disagree
 * about: a host whose last label is numeric/hex/octal trips WHATWG's "ends in a
 * number" rule, so a BROWSER parses the whole host as IPv4 and REJECTS it when
 * that fails; RFC 3986 has no such rule, so `curl` / `requests` / SSRF-prone
 * fetchers accept it as a literal hostname and resolve it. No legitimate site is
 * shaped like this — it is the malformed-IPv4 corner of the yoU-aRe-a-Liar
 * allow-list-bypass class (SecWeb '22), the one scope where cross-reader
 * equivocation is the only signal.
 *
 * Fires when BOTH hold (on the host with a single trailing root dot stripped):
 *  (a) the last non-empty label is all-digits, or `0x`/`0X`-hex, i.e. WHATWG
 *      would attempt IPv4 parsing; AND
 *  (b) a strict whole-host IPv4 parse FAILS (octet > 255, > 4 parts, bad radix,
 *      or a dotless value > 2^32-1).
 *
 * Deliberately DISTINCT from `ip_obfuscation`: that code means "this IS a real
 * obfuscated IP with a canonical form" and hands a decodable address to
 * `ip_classification` for range bucketing. These hosts have NO valid canonical
 * IP, so they must not pollute that handoff — and a browser refusing a host that
 * a non-browser client will resolve is its own, self-explaining signal.
 *
 * Two sub-shapes, SAME medium band (distinct detail for explainability +
 * independent future tuning):
 *  - pure-IP-attempt      — every label is numeric/hex/octal (256.0.0.1,
 *                           0x100.2.3.4, dotless overflow 0x100000000).
 *  - name-with-numeric-tail — ≥1 non-numeric label but a numeric/hex terminal
 *                           label trips the IPv4 path (foo.09, foo.0x4,
 *                           foo.1.2.3.4).
 */

/** All-decimal-digits (covers leading-zero/"octal" forms), or a `0x`/`0X` prefix. */
const NUMERIC_LABEL = /^(?:[0-9]+|0[xX][0-9a-fA-F]*)$/;

/** Does this label make WHATWG attempt IPv4 parsing of the whole host? */
function triggersIpv4Path(label: string): boolean {
  return NUMERIC_LABEL.test(label);
}

export const ambiguousNumericHost: Detector = {
  id: "ambiguous_numeric_host",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.host === "") return [];

    const host = stripTrailingRootDot(ctx.host);
    const labels = host.split(".");
    const last = labels[labels.length - 1];
    // (a) WHATWG would try to read the whole host as IPv4.
    if (last === undefined || last === "" || !triggersIpv4Path(last)) return [];

    // (b) …but a strict whole-host IPv4 parse fails. A non-null analysis means a
    // real (possibly obfuscated) IP — that is ip_obfuscation's job, not ours.
    if (analyzeIpv4(host) !== null) return [];

    // Sub-shape: pure IP attempt when EVERY label is numeric/hex/octal, else a
    // name carrying a numeric/hex tail. Same medium weight; detail differs.
    const pureIpAttempt = labels.every((label) => triggersIpv4Path(label));
    const detail = pureIpAttempt
      ? `host '${ctx.host}' is a malformed IPv4 literal — a browser parses it as an ` +
        `IPv4 address and rejects it, but non-browser clients may resolve it as a hostname`
      : `host '${ctx.host}' ends in a numeric/hex label — a browser parses the whole ` +
        `host as IPv4 and rejects it, but non-browser clients may resolve it as a hostname`;

    return [{ code: "ambiguous_numeric_host", detail }];
  },
};
