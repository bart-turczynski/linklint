import { BlockList, isIP } from "node:net";

import { classifyHost } from "linklint";

import type {
  TransportAddressCategory,
  TransportAddressDecision,
} from "./types.js";

interface SupplementalRule {
  readonly category: TransportAddressCategory;
  readonly family: "ipv4" | "ipv6";
  readonly blockList: BlockList;
}

/** One supplemental range, as written. */
export interface SupplementalRange {
  readonly category: TransportAddressCategory;
  readonly network: string;
  readonly prefix: number;
  readonly family: "ipv4" | "ipv6";
}

/**
 * The supplemental ranges, exported so the drift guard
 * (`test/address-table-consistency.test.ts`) enumerates the REAL table rather
 * than a copy of it — a copy would just be a third independent definition of
 * the same concept (LINK-cmstadju).
 *
 * These are a fail-closed BACKSTOP, not the primary classifier: core is asked
 * first and its answer wins. After S3 (LINK-qvsrmrzv) core's IANA-derived table
 * covers most of this list, so several rules below are currently unreachable —
 * deliberately kept, because at a connection boundary a redundant block is free
 * and a missing one is a live SSRF hole. The guard pins which layer answers for
 * each range, so drift in either direction fails a test instead of going
 * unnoticed.
 */
export const SUPPLEMENTAL_RANGES: readonly SupplementalRange[] = [
  // Core deliberately leaves the documentation prefixes UNCLASSIFIED — they are
  // inert examples, not deception, so they must not affect a verdict. Connecting
  // to one is still pointless, so online blocks them here. This asymmetry is
  // intentional and is the main reason the supplemental table still exists.
  { category: "documentation", network: "192.0.2.0", prefix: 24, family: "ipv4" },
  { category: "documentation", network: "198.51.100.0", prefix: 24, family: "ipv4" },
  { category: "documentation", network: "203.0.113.0", prefix: 24, family: "ipv4" },
  { category: "documentation", network: "2001:db8::", prefix: 32, family: "ipv6" },
  { category: "documentation", network: "3fff::", prefix: 20, family: "ipv6" },
  { category: "benchmark", network: "198.18.0.0", prefix: 15, family: "ipv4" },
  { category: "benchmark", network: "2001:2::", prefix: 48, family: "ipv6" },
  { category: "discard", network: "192.0.0.0", prefix: 24, family: "ipv4" },
  { category: "discard", network: "192.88.99.0", prefix: 24, family: "ipv4" },
  { category: "discard", network: "100::", prefix: 64, family: "ipv6" },
  { category: "discard", network: "5f00::", prefix: 16, family: "ipv6" },
  // Transition wrappers around a PUBLIC IPv4 are the live case: core unwraps
  // them and correctly declines to bucket e.g. `64:ff9b::808:808` (that is NAT64
  // doing its job for 8.8.8.8), but connecting to one would still reach an IPv4
  // destination through an IPv6 literal, so the boundary blocks it.
  { category: "transition", network: "64:ff9b::", prefix: 96, family: "ipv6" },
  { category: "transition", network: "64:ff9b:1::", prefix: 48, family: "ipv6" },
  { category: "transition", network: "::", prefix: 96, family: "ipv6" },
  // 6to4 and Teredo carry NO core bucket by decision (LINK-evooubiz): the IPv4
  // they embed is a router or relay, not the destination, so scoring them would
  // assert something false. Refusing to CONNECT to them needs no such claim.
  { category: "transition", network: "2001::", prefix: 23, family: "ipv6" },
  { category: "transition", network: "2002::", prefix: 16, family: "ipv6" },
  { category: "ip_reserved", network: "::ffff:0:0", prefix: 96, family: "ipv6" },
  // Deprecated site-local (RFC 3879). IANA removed it, so core has no row.
  { category: "ip_reserved", network: "fec0::", prefix: 10, family: "ipv6" },
];

const SUPPLEMENTAL_RULES: readonly SupplementalRule[] = SUPPLEMENTAL_RANGES.map((r) =>
  subnet(r.category, r.network, r.prefix, r.family),
);

/**
 * Fail-closed address decision for the connection boundary. It reuses core's
 * most-specific literal classifier, then blocks additional non-global ranges
 * that are harmless lexical examples but unsafe connection destinations.
 */
export function classifyTransportAddress(address: string): TransportAddressDecision {
  const family = isIP(address);
  if (family !== 4 && family !== 6) {
    return { address, family: null, allowed: false, category: "invalid" };
  }

  const coreClassification = classifyHost(address);
  if (coreClassification) {
    return {
      address,
      family,
      allowed: false,
      category: coreClassification.bucket,
    };
  }

  const familyName = family === 4 ? "ipv4" : "ipv6";
  for (const rule of SUPPLEMENTAL_RULES) {
    if (rule.family === familyName && rule.blockList.check(address, familyName)) {
      return { address, family, allowed: false, category: rule.category };
    }
  }

  return { address, family, allowed: true, category: null };
}

export function addressesEqual(left: string, right: string): boolean {
  const family = isIP(left);
  if ((family !== 4 && family !== 6) || isIP(right) !== family) return false;
  const familyName = family === 4 ? "ipv4" : "ipv6";
  const list = new BlockList();
  list.addAddress(left, familyName);
  return list.check(right, familyName);
}

function subnet(
  category: TransportAddressCategory,
  network: string,
  prefix: number,
  family: "ipv4" | "ipv6",
): SupplementalRule {
  const blockList = new BlockList();
  blockList.addSubnet(network, prefix, family);
  return { category, family, blockList };
}
