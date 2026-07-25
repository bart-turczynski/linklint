import type { Detector, DetectorFinding } from "./types.js";
import type { ReasonCode } from "../schema/reason-codes.js";
import { analyzeIpv4, analyzeIpv6 } from "../parse/ip.js";
import { CLOUD_METADATA_ENDPOINTS } from "../data/cloud-metadata.js";

/**
 * Literal-IP range classifier. Scoring. Classifies a literal IP host into
 * exactly ONE range bucket and emits one reason code naming that bucket. Runs on
 * ALL IP-literal hosts — canonical or obfuscated alike — and reuses the already-
 * decoded canonical/embedded address from `parse/ip.ts` (no IP parsing here).
 *
 * Buckets, most-specific first (emit exactly ONE per address):
 *   ip_cloud_metadata > ip_loopback > ip_link_local > ip_private > ip_reserved
 *
 * IPv4-in-IPv6 embeddings (`::ffff:127.0.0.1`) are classified by the EMBEDDED
 * IPv4 — the SSRF masquerade where a validator sees IPv6 but the resolver
 * reaches an internal v4 target.
 */

type Bucket =
  | "ip_cloud_metadata"
  | "ip_loopback"
  | "ip_link_local"
  | "ip_private"
  | "ip_reserved";

/** A bucket decision, carrying the provider attribution when one applies. */
interface BucketMatch {
  bucket: Bucket;
  /** Cloud vendor owning a matched metadata endpoint; absent for range buckets. */
  provider?: string;
}

/** Parse a canonical dotted-decimal IPv4 (a.b.c.d) into a 32-bit unsigned int. */
function dottedToInt(dotted: string): number {
  const parts = dotted.split(".");
  let n = 0;
  for (const p of parts) n = n * 256 + Number(p);
  return n >>> 0;
}

/**
 * The curated cloud-metadata table (`data/cloud-metadata.ts`), indexed by the
 * PARSED address so lookups compare decoded bits, never text. Each row is run
 * through the same IPv4/IPv6 parser applied to the host under inspection, so an
 * alternate spelling of a row (`fd00:0ec2::254`) or of the host both collapse to
 * the same key. Built once at module load — per-call cost is one Map lookup.
 *
 * A row that fails to parse is skipped rather than thrown on: `inspect()` must
 * never throw, and importing the library must not fail on a data typo. The
 * table-integrity test asserts every row parses, so a typo fails CI loudly
 * instead of degrading silently at runtime.
 */
const METADATA_IPV4 = new Map<number, string>();
const METADATA_IPV6 = new Map<string, string>();
for (const endpoint of CLOUD_METADATA_ENDPOINTS) {
  const v4 = analyzeIpv4(endpoint.address);
  if (v4) {
    METADATA_IPV4.set(dottedToInt(v4.canonical), endpoint.provider);
    continue;
  }
  const v6 = analyzeIpv6(endpoint.address);
  if (v6) METADATA_IPV6.set(v6.canonical, endpoint.provider);
}

/** Classify a canonical dotted-decimal IPv4 into one bucket, or null if public. */
function classifyIpv4(dotted: string): BucketMatch | null {
  const n = dottedToInt(dotted);
  const a = (n >>> 24) & 0xff;
  const b = (n >>> 16) & 0xff;

  // Cloud-metadata endpoint (most specific): the curated per-provider table.
  // Runs FIRST so an endpoint inside a broader special-use range (169.254.169.254
  // in link-local, 100.100.100.200 in CGNAT) classifies as metadata, not range.
  const metadata = METADATA_IPV4.get(n);
  if (metadata !== undefined) return { bucket: "ip_cloud_metadata", provider: metadata };

  // Loopback: 127.0.0.0/8.
  if (a === 127) return { bucket: "ip_loopback" };

  // Link-local: 169.254.0.0/16.
  if (a === 169 && b === 254) return { bucket: "ip_link_local" };

  // Private (RFC 1918): 10/8, 172.16/12, 192.168/16.
  if (a === 10) return { bucket: "ip_private" };
  if (a === 172 && b >= 16 && b <= 31) return { bucket: "ip_private" };
  if (a === 192 && b === 168) return { bucket: "ip_private" };

  // Reserved / special-use: 0/8, 100.64/10 (CGNAT), multicast 224/4, 240/4.
  if (a === 0) return { bucket: "ip_reserved" };
  if (a === 100 && b >= 64 && b <= 127) return { bucket: "ip_reserved" };
  if (a >= 224) return { bucket: "ip_reserved" }; // 224/4 multicast + 240/4 future-use

  // Otherwise an ordinary public IPv4 — no bucket.
  return null;
}

/** Classify a canonical RFC 5952 IPv6 string into exactly one bucket, or null. */
function classifyIpv6(canonical: string): BucketMatch | null {
  const c = canonical.toLowerCase();
  const head = c.split(":")[0] ?? "";

  // Cloud-metadata IPv6 endpoint (most specific): the curated per-provider
  // table, keyed by the RFC 5952 canonical form. Both sides of the comparison
  // are parsed and re-rendered, so `fd00:0ec2::254` and `FD00:EC2:0:0:0:0:0:254`
  // match the same row as `fd00:ec2::254` — a text prefix test would not.
  const metadata = METADATA_IPV6.get(c);
  if (metadata !== undefined) return { bucket: "ip_cloud_metadata", provider: metadata };

  // Loopback: ::1/128.
  if (c === "::1") return { bucket: "ip_loopback" };

  // Link-local: fe80::/10 — first hextet in fe80..febf.
  const headVal = /^[0-9a-f]{1,4}$/.test(head) ? parseInt(head, 16) : NaN;
  if (!Number.isNaN(headVal) && headVal >= 0xfe80 && headVal <= 0xfebf) {
    return { bucket: "ip_link_local" };
  }

  // Unique-local (private): fc00::/7 — first hextet in fc00..fdff.
  if (!Number.isNaN(headVal) && headVal >= 0xfc00 && headVal <= 0xfdff) {
    return { bucket: "ip_private" };
  }

  // Reserved: unspecified ::/128, multicast ff00::/8 (first hextet ff00..ffff).
  if (c === "::") return { bucket: "ip_reserved" };
  if (!Number.isNaN(headVal) && headVal >= 0xff00 && headVal <= 0xffff) {
    return { bucket: "ip_reserved" };
  }

  // Anything else (e.g. 2001:db8::1) is public/unclassified — no bucket.
  return null;
}

const SUMMARY: Record<Bucket, string> = {
  ip_cloud_metadata: "the cloud instance-metadata endpoint (SSRF target)",
  ip_loopback: "a loopback address",
  ip_link_local: "a link-local address",
  ip_private: "a private (internal) address",
  ip_reserved: "a reserved / special-use address",
};

/** A classified literal-IP host: its range bucket plus display/canonical forms. */
export interface IpClassification {
  bucket: Bucket;
  /** Host as shown in detail strings (IPv6 wrapped in brackets). */
  shown: string;
  /** Canonical address that determined the bucket. */
  canonical: string;
  /**
   * Cloud vendor owning the matched metadata endpoint, from the curated
   * `data/cloud-metadata.ts` table. Present only on `ip_cloud_metadata`; the
   * generic range buckets have no provider.
   */
  provider?: string;
}

/**
 * Classify `ctx.host` into exactly one range bucket, or null for a public /
 * non-IP host. Shared by the always-on `ipClassification` detector and the
 * agentMode SSRF escalation so the range logic lives in one place.
 */
export function classifyHost(host: string): IpClassification | null {
  if (host === "") return null;

  const ip4 = analyzeIpv4(host);
  if (ip4) {
    const m = classifyIpv4(ip4.canonical);
    return m ? { ...m, shown: host, canonical: ip4.canonical } : null;
  }

  const ip6 = analyzeIpv6(host);
  if (ip6) {
    // IPv4-in-IPv6 embedding: classify by the embedded IPv4 (SSRF masquerade).
    if (ip6.embeddedIpv4) {
      const m = classifyIpv4(ip6.embeddedIpv4);
      return m ? { ...m, shown: `[${host}]`, canonical: ip6.embeddedIpv4 } : null;
    }
    const m = classifyIpv6(ip6.canonical);
    if (m) return { ...m, shown: `[${host}]`, canonical: ip6.canonical };
  }

  return null;
}

export const ipClassification: Detector = {
  id: "ip_classification",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const c = classifyHost(ctx.host);
    return c ? [finding(c)] : [];
  },
};

/**
 * Bucket wording for the detail string. A matched metadata endpoint names the
 * owning cloud provider so the reader learns WHOSE credentials are at stake;
 * every other bucket keeps its generic phrasing.
 */
function summaryFor(c: IpClassification): string {
  if (c.bucket === "ip_cloud_metadata" && c.provider !== undefined) {
    return `the ${c.provider} instance-metadata endpoint (SSRF target)`;
  }
  return SUMMARY[c.bucket];
}

function finding(c: IpClassification): DetectorFinding {
  return {
    code: c.bucket as ReasonCode,
    detail: `host '${c.shown}' resolves to ${summaryFor(c)} (${c.canonical})`,
  };
}
