import { stripInvisible } from "../unicode/format-chars.js";
import { toUnicode } from "../unicode/idna.js";
import { analyzeIpv4, analyzeIpv6 } from "./ip.js";
import { analyzeHost, type PslResult } from "./psl.js";

/**
 * Facts derived from a raw host: the cleaned host, whether it is an IP literal,
 * its PSL decomposition, its Unicode form, and its labels. This is the stable
 * "facts derived from what was written" object — derived once from `RawParts`
 * and consumed by both the public `ParsedUrl` and the internal
 * `InspectionContext`. Future derived layers can extend this without forcing
 * new fields through the syntax parser.
 */
export interface HostFacts {
  /** Host with invisible/format characters stripped; `""` when hostless. */
  host: string;
  /** True when `host` is an IPv4 (canonical/obfuscated) or IPv6 literal. */
  isIp: boolean;
  /** PSL decomposition (registrable domain / public suffix / subdomain). */
  psl: PslResult;
  /** Unicode (IDNA) form of `host`; equals `host` for IPs and hostless inputs. */
  hostUnicode: string;
  /** Host labels split on `.` (a single element for IPv6 literals). */
  hostLabels: string[];
}

/**
 * Derive host facts from a raw host string (the `rawHost` of `RawParts`).
 *
 * An IP host (IPv4 canonical/obfuscated, or an IPv6 literal) is never a
 * registrable domain — its PSL fields are nulled so domain-based detectors
 * (embedded_domain, risky_tld) skip it. IPs also have no Unicode/IDN form.
 */
export function deriveHostFacts(rawHost: string): HostFacts {
  // The parser preserves `rawHost` verbatim (it only strips invisibles when
  // validating); strip them here so the derived host is the canonical form.
  const host = stripInvisible(rawHost);
  const isIpv4 = host !== "" && analyzeIpv4(host) !== null;
  const isIp = isIpv4 || (host !== "" && host.includes(":") && analyzeIpv6(host) !== null);
  const psl: PslResult = host === "" || isIp ? emptyPsl(isIp) : analyzeHost(host);
  const hostUnicode = host === "" || isIp ? host : toUnicode(host);
  const hostLabels =
    host === "" ? [] : isIp && host.includes(":") ? [host] : host.replace(/\.$/, "").split(".");

  return { host, isIp, psl, hostUnicode, hostLabels };
}

function emptyPsl(isIp = false): PslResult {
  return { registrableDomain: null, publicSuffix: null, subdomain: null, isIp };
}
