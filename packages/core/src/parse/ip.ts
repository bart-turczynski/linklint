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
 * Strip a SINGLE trailing root dot (the FQDN `example.com.` form). Both IPv4
 * recognition and the ambiguous-numeric-host detector treat `1.2.3.08.` exactly
 * like `1.2.3.08` — the root dot is a no-op for the address. A second trailing
 * dot (`1.2.3.08..`) is genuinely malformed (empty label) and left intact so it
 * still fails to parse. The bare `"."` root is left as-is (not an address).
 */
export function stripTrailingRootDot(host: string): string {
  return host.length > 1 && host.endsWith(".") ? host.slice(0, -1) : host;
}

/**
 * Analyze a host as a possible IPv4. Returns null if it is not an IPv4 at all.
 */
export function analyzeIpv4(host: string): Ipv4Analysis | null {
  // A single trailing root dot is an FQDN no-op: `1.2.3.08.` is the same address
  // as `1.2.3.08`. Normalizing here fixes the inconsistency where the dotted form
  // was recognized (ip_obfuscation) but the trailing-dot form silently was not.
  const parts = stripTrailingRootDot(host).split(".");
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

/**
 * Obfuscated-IPv6 recognition. Extends FR-D-7 to IPv6 literals (the inner
 * text of `[...]`, brackets already stripped). Returns null if the string is not
 * a valid IPv6 address at all; otherwise renders the RFC 5952 canonical form and
 * flags non-canonical / IPv4-embedding forms as obfuscated.
 */
export interface Ipv6Analysis {
  /** True if the literal is a non-canonical (obfuscated) IPv6 form. */
  obfuscated: boolean;
  /** RFC 5952 canonical form (lowercase, `::` for the longest zero run). */
  canonical: string;
  /**
   * Dotted-decimal IPv4 carried in the LOW 32 BITS behind one of the RFC
   * transition wrapper prefixes (see {@link LOW32_WRAPPERS}), else null.
   *
   * Read from the DECODED BITS, not from the spelling: `::ffff:127.0.0.1` and
   * `::ffff:7f00:1` are the same 128 bits and both yield `127.0.0.1`.
   */
  embeddedIpv4: string | null;
  /**
   * The wrapper prefix that carried `embeddedIpv4`, named for reason detail
   * (e.g. `NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)`). Absent whenever
   * `embeddedIpv4` is null.
   */
  embeddedIpv4Via?: string;
}

/** An IPv4 recovered from a transition wrapper prefix, plus the wrapper's name. */
interface EmbeddedIpv4 {
  address: string;
  mechanism: string;
}

/**
 * The RFC transition wrappers that place the IPv4 in the LOW 32 BITS of the
 * IPv6 address, so recovery is a plain read of the last two hextets — no u-byte
 * skipping, no bit-complementing, no arithmetic on the prefix.
 *
 * `hextets` fixes the upper 96 bits; a literal matches when hextets 0-5 are
 * exactly these values.
 *
 * DELIBERATELY EXCLUDED (they do NOT put the IPv4 in the low 32 bits, so the
 * same read would decode garbage): 6to4 `2002::/16` (gateway IPv4 in hextets
 * 1-2), Teredo `2001::/32` (server IPv4 after the prefix, client IPv4
 * bit-complemented at the tail), the RFC 6052 network-specific prefixes at
 * /32../64 (IPv4 straddles the reserved u-byte at octet 8) and the RFC 8215
 * local-use NAT64 prefix `64:ff9b:1::/48`.
 */
const LOW32_WRAPPERS: ReadonlyArray<{
  hextets: readonly [number, number, number, number, number, number];
  mechanism: string;
  /**
   * Low-32 values that are NOT an embedded IPv4 for this wrapper. Only the
   * IPv4-compatible prefix needs one: under `::/96` the low-32 values 0 and 1
   * are the unspecified address `::` and the loopback `::1`, which are their own
   * addresses (`ip_reserved` / `ip_loopback`), not wrapped 0.0.0.0 / 0.0.0.1.
   */
  excludeLow?: readonly number[];
}> = [
  // RFC 4291 §2.5.5.2 IPv4-mapped — how a dual-stack socket reports an IPv4 peer.
  { hextets: [0, 0, 0, 0, 0, 0xffff], mechanism: "IPv4-mapped prefix ::ffff:0:0/96" },
  // RFC 6052 §2.1 NAT64 well-known prefix — an IPv6-only client's route to IPv4.
  {
    hextets: [0x64, 0xff9b, 0, 0, 0, 0],
    mechanism: "NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)",
  },
  // RFC 4291 §2.5.5.1 IPv4-compatible — deprecated, still parsed and still routed.
  {
    hextets: [0, 0, 0, 0, 0, 0],
    mechanism: "IPv4-compatible prefix ::/96 (deprecated by RFC 4291)",
    excludeLow: [0, 1],
  },
];

/**
 * Recover the IPv4 wrapped by one of {@link LOW32_WRAPPERS}, or null. Pure
 * integer/bit work on the already-decoded hextets — no re-parsing, no strings
 * until a match is found, so the hot path stays inside the perf budget.
 */
function unwrapLow32Ipv4(groups: number[]): EmbeddedIpv4 | null {
  for (const wrapper of LOW32_WRAPPERS) {
    let matched = true;
    for (let i = 0; i < 6; i++) {
      if (groups[i] !== wrapper.hextets[i]) {
        matched = false;
        break;
      }
    }
    if (!matched) continue;
    const low = ((groups[6]! << 16) | groups[7]!) >>> 0;
    if (wrapper.excludeLow?.includes(low)) return null;
    return { address: toDotted(low), mechanism: wrapper.mechanism };
  }
  return null;
}

/** Parse a strict canonical dotted-decimal IPv4 (no octal/hex/leading-zero). */
function parseStrictDottedQuad(s: string): number | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part[0] === "0") return null; // no leading zeros
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

/**
 * Parse a colon-separated run of IPv6 hextets, with an optional trailing IPv4.
 * A dotted quad is folded straight into two hextets: the spelling is discarded
 * here on purpose so that recognizing a wrapped IPv4 is a question about the
 * BITS, asked once in {@link unwrapLow32Ipv4}.
 */
function parseHextets(s: string): number[] | null {
  if (s === "") return [];
  const parts = s.split(":");
  const groups: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p.includes(".")) {
      if (i !== parts.length - 1) return null; // dotted-quad only in the final position
      const v4 = parseStrictDottedQuad(p);
      if (v4 === null) return null;
      groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
    } else {
      if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
      groups.push(parseInt(p, 16));
    }
  }
  return groups;
}

/** Render 8 hextets as the RFC 5952 canonical string (longest zero run → `::`). */
function canonicalizeIpv6(groups: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  const head = hex.slice(0, bestStart).join(":");
  const tail = hex.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

/** Analyze a host as a possible IPv6 literal. Returns null if it is not one. */
export function analyzeIpv6(host: string): Ipv6Analysis | null {
  // Must look like IPv6; reject zone IDs (`fe80::1%eth0`) — keep them invalid.
  if (host === "" || !host.includes(":") || host.includes("%")) return null;
  if ((host.match(/::/g) ?? []).length > 1) return null; // at most one `::`

  let groups: number[];
  const dbl = host.indexOf("::");
  if (dbl !== -1) {
    const left = parseHextets(host.slice(0, dbl));
    const right = parseHextets(host.slice(dbl + 2));
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null; // `::` must elide at least one zero group
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const all = parseHextets(host);
    if (!all) return null;
    groups = all;
  }
  if (groups.length !== 8) return null;

  const canonical = canonicalizeIpv6(groups);
  // Obfuscated when the input as written is not already the canonical form
  // (uppercase, leading zeros, unnecessary/uncompressed zero groups, or a
  // dotted-quad tail — `::ffff:127.0.0.1` never equals `::ffff:7f00:1`).
  //
  // Wrapping an IPv4 is NOT itself obfuscation: `::ffff:808:808` is the exact
  // RFC 5952 spelling of its own bits and hides nothing. What the wrapper does
  // is change WHERE the address points, which is the ip_classification
  // detector's business (via `embeddedIpv4`), not this flag's.
  const obfuscated = host.toLowerCase() !== canonical;
  const embedded = unwrapLow32Ipv4(groups);
  return embedded
    ? {
        obfuscated,
        canonical,
        embeddedIpv4: embedded.address,
        embeddedIpv4Via: embedded.mechanism,
      }
    : { obfuscated, canonical, embeddedIpv4: null };
}
