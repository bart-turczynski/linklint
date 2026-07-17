import { hasMalformedPunycode } from "./idna.js";

/**
 * Punycode (RFC 3492) failure taxonomy for the `punycode_malformed` detector
 * (P1 / LINK-dynjdiax). Mirrors the stable error taxonomy punycoder ships
 * (src/punycoder_errors.cpp / punycoder_algorithm.cpp), conformance-tested vs
 * RFC 3492 vectors, so a single boolean "malformed" flag becomes a specific,
 * self-explaining reason.
 *
 * Firing stays governed by tr46 (`hasMalformedPunycode`), so this NEVER changes
 * WHICH hosts flag — only the detail. The decode-level sub-codes below are a
 * strict subset of the labels tr46 rejects; a label that decodes and round-trips
 * cleanly but tr46 still rejects (a UTS-46 U-label validity rule: bidi,
 * combining-mark-initial, hyphen position, …) is reported as `invalid_idna_label`.
 */
export type PunycodeSubCode =
  | "empty_ace_payload"
  | "invalid_punycode_digit"
  | "truncated_punycode_input"
  | "punycode_overflow"
  | "decoded_code_point_out_of_range"
  | "non_canonical_encoding"
  | "invalid_idna_label";

/** One-line, human-readable gloss per sub-code (used in the detector detail). */
const SUBCODE_DESCRIPTION: Record<PunycodeSubCode, string> = {
  empty_ace_payload: "the xn-- prefix has no payload to decode",
  invalid_punycode_digit: "the payload contains a non-base-36 digit",
  truncated_punycode_input: "a generalized-integer sequence ends early",
  punycode_overflow: "delta/bias arithmetic overflowed during decode",
  decoded_code_point_out_of_range: "a decoded code point is a surrogate or above U+10FFFF",
  non_canonical_encoding: "decodes but is not the canonical encoding (fails the A-label round-trip)",
  invalid_idna_label: "decodes but is not a valid IDNA U-label",
};

// RFC 3492 §5 parameters.
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
// Bound on the accumulator/place-value, matching a 32-bit reference decoder; any
// overflow past it is a `punycode_overflow` rather than a silent wrap.
const MAXINT = 0x7fffffff;

class PunycodeError extends Error {
  constructor(readonly subCode: PunycodeSubCode) {
    super(subCode);
  }
}

function decodeDigit(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30 + 26; // 0-9 → 26-35
  if (c >= 0x61 && c <= 0x7a) return c - 0x61; // a-z → 0-25
  if (c >= 0x41 && c <= 0x5a) return c - 0x41; // A-Z → 0-25
  return -1;
}

function encodeDigit(d: number): number {
  return d < 26 ? d + 0x61 : d - 26 + 0x30;
}

function threshold(k: number, bias: number): number {
  if (k <= bias) return TMIN;
  if (k >= bias + TMAX) return TMAX;
  return k - bias;
}

function adapt(delta: number, numpoints: number, first: boolean): number {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numpoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function isUnicodeScalar(n: number): boolean {
  return n >= 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff);
}

/**
 * Decode a full ACE label (`xn--…`, already lower-cased) to its code points.
 * Throws a {@link PunycodeError} carrying the specific decode failure. A faithful
 * port of RFC 3492 §6.2 with checked arithmetic (mirrors punycoder's fallback
 * decoder).
 */
function decodeAceLabel(label: string): number[] {
  const start = 4; // past "xn--"
  if (label.length === start) throw new PunycodeError("empty_ace_payload");

  const output: number[] = [];
  let index = start;
  // Basic code points sit before the LAST hyphen (the delimiter); everything
  // after it is the variable-length integer payload.
  const lastHyphen = label.lastIndexOf("-");
  if (lastHyphen >= start) {
    for (let j = start; j < lastHyphen; j++) {
      output.push(label.charCodeAt(j));
    }
    index = lastHyphen + 1;
  }

  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  while (index < label.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= label.length) throw new PunycodeError("truncated_punycode_input");
      const digit = decodeDigit(label.charCodeAt(index++));
      if (digit < 0) throw new PunycodeError("invalid_punycode_digit");
      if (digit > Math.floor((MAXINT - i) / w)) throw new PunycodeError("punycode_overflow");
      i += digit * w;
      const t = threshold(k, bias);
      if (digit < t) break;
      if (w > Math.floor(MAXINT / (BASE - t))) throw new PunycodeError("punycode_overflow");
      w *= BASE - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    const increment = Math.floor(i / outLen);
    if (increment > MAXINT - n) throw new PunycodeError("punycode_overflow");
    n += increment;
    i %= outLen;
    if (!isUnicodeScalar(n)) throw new PunycodeError("decoded_code_point_out_of_range");
    output.splice(i, 0, n);
    i++;
  }
  return output;
}

/**
 * Re-encode code points to an ACE label (RFC 3492 §6.3). Returns `null` when the
 * input is all-ASCII (no IDN → there is no canonical `xn--` form, so an `xn--`
 * label that decodes to pure ASCII is by definition non-canonical).
 */
function encodeAceLabel(codepoints: number[]): string | null {
  if (!codepoints.some((c) => c >= 0x80)) return null;

  let out = "xn--";
  let basic = 0;
  let handled = 0;
  for (const cp of codepoints) {
    if (cp < 0x80) {
      out += String.fromCharCode(cp);
      basic++;
      handled++;
    }
  }
  if (basic > 0) out += "-";

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  const total = codepoints.length;
  while (handled < total) {
    let m = MAXINT;
    for (const cp of codepoints) if (cp >= n && cp < m) m = cp;
    delta += (m - n) * (handled + 1);
    n = m;
    for (const cp of codepoints) {
      if (cp < n) delta++;
      if (cp === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = threshold(k, bias);
          if (q < t) break;
          out += String.fromCharCode(encodeDigit(t + ((q - t) % (BASE - t))));
          q = Math.floor((q - t) / (BASE - t));
        }
        out += String.fromCharCode(encodeDigit(q));
        bias = adapt(delta, handled + 1, handled === basic);
        delta = 0;
        handled++;
      }
    }
    delta++;
    n++;
  }
  return out;
}

/**
 * Classify a single ACE label: its decode-level failure, `non_canonical_encoding`
 * if it decodes but fails the A-label round-trip (RFC 5891 §5.4), or `null` when
 * it decodes and round-trips cleanly. Case is folded first, so uppercase ACE
 * (which is valid) is never reported as non-canonical.
 */
export function classifyAceLabel(label: string): PunycodeSubCode | null {
  const lower = label.toLowerCase();
  let codepoints: number[];
  try {
    codepoints = decodeAceLabel(lower);
  } catch (e) {
    if (e instanceof PunycodeError) return e.subCode;
    throw e; // never expected; do not mask a real bug
  }
  // A-label canonical round-trip: decode → re-encode must be byte-identical.
  if (encodeAceLabel(codepoints) !== lower) return "non_canonical_encoding";
  return null;
}

/** A malformed ACE label with its specific failure and a human-readable gloss. */
export interface MalformedPunycode {
  /** The offending `xn--` label. */
  label: string;
  /** The specific failure mode. */
  subCode: PunycodeSubCode;
  /** One-line description of the sub-code. */
  description: string;
}

/**
 * Analyze a host for a malformed ACE label, returning the specific failure of
 * the FIRST offending label (or `null` when the host is fine). Firing is gated
 * by tr46 (`hasMalformedPunycode`) so this changes WHICH hosts flag exactly not
 * at all — only which sub-code is reported. A tr46 rejection with no decode-level
 * failure (a UTS-46 U-label validity rule) is reported as `invalid_idna_label`.
 */
export function analyzeMalformedPunycode(host: string): MalformedPunycode | null {
  if (host === "" || !hasMalformedPunycode(host)) return null;

  const aceLabels = host.split(".").filter((l) => /^xn--/i.test(l));
  for (const label of aceLabels) {
    const subCode = classifyAceLabel(label);
    if (subCode) return { label, subCode, description: SUBCODE_DESCRIPTION[subCode] };
  }
  // tr46 rejects the host but every ACE label decodes + round-trips: the failure
  // is a U-label validity rule, not a Punycode decode error.
  const label = aceLabels[0] ?? host;
  return {
    label,
    subCode: "invalid_idna_label",
    description: SUBCODE_DESCRIPTION.invalid_idna_label,
  };
}
