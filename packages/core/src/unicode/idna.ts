import tr46 from "tr46";

/**
 * UTS-46 / IDNA helpers backed by the vetted pure-JS `tr46` implementation
 * (FR-LIB-1: do not hand-roll IDNA). All functions are total — they never throw
 * and fall back to the input on processing failure.
 */

/** ASCII (ACE / punycode) form of a host, or the input if conversion fails. */
export function toAscii(host: string): string {
  try {
    const ace = tr46.toASCII(host, { transitionalProcessing: false });
    return ace ?? host;
  } catch {
    return host;
  }
}

/** Unicode (U-label) form of a host — decodes `xn--` labels. Falls back to input. */
export function toUnicode(host: string): string {
  try {
    const { domain } = tr46.toUnicode(host, { transitionalProcessing: false });
    return domain || host;
  } catch {
    return host;
  }
}

/**
 * True if `host` has an `xn--` (ACE) label that fails UTS-46/Punycode decoding —
 * i.e. it does not decode to a valid U-label (FR-D / E5). `tr46.toUnicode`
 * surfaces this via its `error` flag, which `toUnicode` above discards. Scoped
 * strictly to ACE labels: a non-ASCII host that merely contains other issues is
 * out of scope here. An uppercase ACE label (e.g. `XN--CAF-DMA`) round-trips
 * after UTS-46 case-folding and is NOT malformed.
 */
export function hasMalformedPunycode(host: string): boolean {
  if (host === "") return false;
  if (!/(^|\.)xn--/i.test(host)) return false;
  try {
    return tr46.toUnicode(host, { transitionalProcessing: false }).error === true;
  } catch {
    // tr46 is total in practice; treat an unexpected throw as non-malformed
    // rather than risk a false positive.
    return false;
  }
}

/** True if the host has a normalization delta: it is an IDN (non-ASCII or ACE). */
export function hasNormalizationDelta(host: string): boolean {
  if (host === "") return false;
  for (const ch of host) {
    if (ch.codePointAt(0)! > 0x7f) return true; // non-ASCII U-label
  }
  // ACE form: any `xn--` label is the punycode encoding of an IDN.
  return /(^|\.)xn--/i.test(host);
}
