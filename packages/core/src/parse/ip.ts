/**
 * Obfuscated-IPv4 recognition (FR-D-7). Implements inet_aton-style parsing so we
 * can detect decimal/octal/hex and dotless forms and render the canonical dotted
 * IP. Canonical dotted-decimal IPs (e.g. `127.0.0.1`) are NOT obfuscation and
 * return `{ obfuscated: false }`.
 */
export interface Ipv4Analysis {
  /** True if this is an IPv4 in a non-canonical (obfuscated) form. */
  obfuscated: boolean;
  /** Canonical `a.b.c.d`, present whenever the host is a valid IPv4. */
  canonical: string;
}

/** Parse one inet_aton part; returns { value, hadHexOrOctal, leadingZero } or null. */
function parsePart(part: string): { value: number; nonDecimal: boolean } | null {
  if (part === "") return null;
  let value: number;
  let nonDecimal = false;
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
    value = parseInt(part.slice(2), 16);
    nonDecimal = true;
  } else if (/^0[0-7]+$/.test(part)) {
    value = parseInt(part, 8);
    nonDecimal = true;
  } else if (/^[0-9]+$/.test(part)) {
    // Leading zero on a multi-digit decimal is itself an octal-style obfuscation.
    nonDecimal = part.length > 1 && part[0] === "0";
    value = parseInt(part, 10);
  } else {
    return null;
  }
  if (!Number.isFinite(value)) return null;
  return { value, nonDecimal };
}

/** Render a 32-bit unsigned int as dotted-decimal. */
function toDotted(n: number): string {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

/**
 * Analyze a host as a possible IPv4. Returns null if it is not an IPv4 at all.
 */
export function analyzeIpv4(host: string): Ipv4Analysis | null {
  const parts = host.split(".");
  if (parts.length === 0 || parts.length > 4) return null;

  const parsed = parts.map(parsePart);
  if (parsed.some((p) => p === null)) return null;
  const vals = parsed as Array<{ value: number; nonDecimal: boolean }>;

  const nonDecimal = vals.some((p) => p.nonDecimal);

  // inet_aton packing: leading parts are single bytes; the final part fills the
  // remaining low-order bytes. Use arithmetic (not bit-shifts) to stay exact for
  // the full 32-bit range.
  const last = vals[vals.length - 1]!.value;
  const remainingBytes = 4 - (vals.length - 1);
  if (last >= 2 ** (8 * remainingBytes)) return null;

  let full = 0;
  for (let i = 0; i < vals.length - 1; i++) {
    if (vals[i]!.value > 0xff) return null; // leading parts must be single bytes
    full = full * 256 + vals[i]!.value;
  }
  full = full * 2 ** (8 * remainingBytes) + last;
  if (full > 0xffffffff) return null;

  const canonical = toDotted(full >>> 0);
  // Obfuscated when any non-decimal part, or fewer than 4 dotted parts.
  const obfuscated = nonDecimal || vals.length !== 4;
  return { obfuscated, canonical };
}
