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

const SUPPLEMENTAL_RULES: readonly SupplementalRule[] = [
  subnet("documentation", "192.0.2.0", 24, "ipv4"),
  subnet("documentation", "198.51.100.0", 24, "ipv4"),
  subnet("documentation", "203.0.113.0", 24, "ipv4"),
  subnet("documentation", "2001:db8::", 32, "ipv6"),
  subnet("documentation", "3fff::", 20, "ipv6"),
  subnet("benchmark", "198.18.0.0", 15, "ipv4"),
  subnet("benchmark", "2001:2::", 48, "ipv6"),
  subnet("discard", "192.0.0.0", 24, "ipv4"),
  subnet("discard", "192.88.99.0", 24, "ipv4"),
  subnet("discard", "100::", 64, "ipv6"),
  subnet("discard", "5f00::", 16, "ipv6"),
  subnet("transition", "64:ff9b::", 96, "ipv6"),
  subnet("transition", "64:ff9b:1::", 48, "ipv6"),
  subnet("transition", "::", 96, "ipv6"),
  subnet("transition", "2001::", 23, "ipv6"),
  subnet("transition", "2002::", 16, "ipv6"),
  subnet("ip_reserved", "::ffff:0:0", 96, "ipv6"),
  subnet("ip_reserved", "fec0::", 10, "ipv6"),
];

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
