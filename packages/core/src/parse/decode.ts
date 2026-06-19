/**
 * Bounded percent-decoding (FR-D-10, architecture §4.1.1). Recursive decoding is
 * capped so adversarial input cannot create a decode-bomb or unbounded CPU path.
 */

/** Default cap on recursive decode passes. */
export const DEFAULT_MAX_DECODE_DEPTH = 4;

const PERCENT_SEQ = /%[0-9a-fA-F]{2}/g;

/** Decode valid `%XX` sequences once (byte-wise); leaves malformed `%` as-is. */
export function decodeOnce(s: string): string {
  return s.replace(PERCENT_SEQ, (m) => String.fromCharCode(parseInt(m.slice(1), 16)));
}

export interface BoundedDecode {
  decoded: string;
  /** Number of decode passes that changed the string (>1 ⇒ nested encoding). */
  passes: number;
  /** True if decoding hit the depth cap before stabilizing. */
  truncated: boolean;
}

/** Repeatedly percent-decode until stable or `maxDepth` passes are exhausted. */
export function boundedDecode(input: string, maxDepth = DEFAULT_MAX_DECODE_DEPTH): BoundedDecode {
  let cur = input;
  let passes = 0;
  while (passes < maxDepth) {
    const next = decodeOnce(cur);
    if (next === cur) return { decoded: cur, passes, truncated: false };
    cur = next;
    passes++;
  }
  // One more check: if it would still change, we truncated.
  const truncated = decodeOnce(cur) !== cur;
  return { decoded: cur, passes, truncated };
}
