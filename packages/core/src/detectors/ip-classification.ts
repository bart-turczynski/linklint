import type { Detector, DetectorFinding } from "./types.js";
import type { ReasonCode } from "../schema/reason-codes.js";
import { analyzeIpv4, analyzeIpv6 } from "../parse/ip.js";

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

/** Parse a canonical dotted-decimal IPv4 (a.b.c.d) into a 32-bit unsigned int. */
function dottedToInt(dotted: string): number {
  const parts = dotted.split(".");
  let n = 0;
  for (const p of parts) n = n * 256 + Number(p);
  return n >>> 0;
}

/** Classify a canonical dotted-decimal IPv4 into one bucket, or null if public. */
function classifyIpv4(dotted: string): Bucket | null {
  const n = dottedToInt(dotted);
  const a = (n >>> 24) & 0xff;
  const b = (n >>> 16) & 0xff;

  // Cloud-metadata endpoint (most specific): 169.254.169.254/32.
  if (n === 0xa9fea9fe) return "ip_cloud_metadata";

  // Loopback: 127.0.0.0/8.
  if (a === 127) return "ip_loopback";

  // Link-local: 169.254.0.0/16.
  if (a === 169 && b === 254) return "ip_link_local";

  // Private (RFC 1918): 10/8, 172.16/12, 192.168/16.
  if (a === 10) return "ip_private";
  if (a === 172 && b >= 16 && b <= 31) return "ip_private";
  if (a === 192 && b === 168) return "ip_private";

  // Reserved / special-use: 0/8, 100.64/10 (CGNAT), multicast 224/4, 240/4.
  if (a === 0) return "ip_reserved";
  if (a === 100 && b >= 64 && b <= 127) return "ip_reserved";
  if (a >= 224) return "ip_reserved"; // 224/4 multicast + 240/4 future-use

  // Otherwise an ordinary public IPv4 — no bucket.
  return null;
}

/** Classify a canonical RFC 5952 IPv6 string into exactly one bucket, or null. */
function classifyIpv6(canonical: string): Bucket | null {
  const c = canonical.toLowerCase();
  const head = c.split(":")[0] ?? "";

  // Cloud-metadata IPv6 endpoint (most specific): fd00:ec2::254.
  if (c === "fd00:ec2::254") return "ip_cloud_metadata";

  // Loopback: ::1/128.
  if (c === "::1") return "ip_loopback";

  // Link-local: fe80::/10 — first hextet in fe80..febf.
  const headVal = /^[0-9a-f]{1,4}$/.test(head) ? parseInt(head, 16) : NaN;
  if (!Number.isNaN(headVal) && headVal >= 0xfe80 && headVal <= 0xfebf) return "ip_link_local";

  // Unique-local (private): fc00::/7 — first hextet in fc00..fdff.
  if (!Number.isNaN(headVal) && headVal >= 0xfc00 && headVal <= 0xfdff) return "ip_private";

  // Reserved: unspecified ::/128, multicast ff00::/8 (first hextet ff00..ffff).
  if (c === "::") return "ip_reserved";
  if (!Number.isNaN(headVal) && headVal >= 0xff00 && headVal <= 0xffff) return "ip_reserved";

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
    const bucket = classifyIpv4(ip4.canonical);
    return bucket ? { bucket, shown: host, canonical: ip4.canonical } : null;
  }

  const ip6 = analyzeIpv6(host);
  if (ip6) {
    // IPv4-in-IPv6 embedding: classify by the embedded IPv4 (SSRF masquerade).
    if (ip6.embeddedIpv4) {
      const bucket = classifyIpv4(ip6.embeddedIpv4);
      return bucket ? { bucket, shown: `[${host}]`, canonical: ip6.embeddedIpv4 } : null;
    }
    const bucket = classifyIpv6(ip6.canonical);
    if (bucket) return { bucket, shown: `[${host}]`, canonical: ip6.canonical };
  }

  return null;
}

export const ipClassification: Detector = {
  id: "ip_classification",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const c = classifyHost(ctx.host);
    return c ? [finding(c.bucket, c.shown, c.canonical)] : [];
  },
};

function finding(bucket: Bucket, shown: string, canonical: string): DetectorFinding {
  return {
    code: bucket as ReasonCode,
    detail: `host '${shown}' resolves to ${SUMMARY[bucket]} (${canonical})`,
  };
}
