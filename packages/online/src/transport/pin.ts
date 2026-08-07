/**
 * Shared destination pinning: the single SSRF/DNS-pinning decision used by BOTH
 * the fetch path and the TLS-observation path (LINK-fgdawgnj, M7a).
 *
 * Given a hostname, it resolves (or accepts a literal), rejects malformed answers,
 * classifies every answer through {@link classifyTransportAddress}, blocks the whole
 * request if any answer is prohibited, and selects the first allowed address to pin.
 * Resolver errors propagate unchanged so each caller maps them into its own
 * outcome vocabulary. Keeping this in one place means a policy change cannot make the
 * observe path more permissive than fetch, or vice versa.
 *
 * "Every answer" is scoped to the set the injected {@link ResolverPort} returned for
 * this call — for the built-in `NodeResolver` that is one
 * `dns.lookup(hostname, { all: true, verbatim: true })`, i.e. `getaddrinfo` subject to
 * the platform's hosts file/`nsswitch` sources, the stub-resolver cache, RFC 6724
 * filtering and `AI_ADDRCONFIG`. It is not an authoritative A/AAAA RRset and carries no
 * TTL. The property this function holds is closure over that returned set, not its
 * completeness: `selected` is always a member of `resolvedAddresses`, and every member
 * is classified before one is chosen (`LINK-rbghrpru`).
 */

import { isIP } from "node:net";

import { classifyTransportAddress } from "./address.js";
import type { DnsAddress, ResolverPort, TransportAddressCategory } from "./types.js";

export interface PinnedDestination {
  readonly kind: "pinned";
  readonly resolvedAddresses: readonly string[];
  readonly selected: DnsAddress;
}

export type PinResult =
  | PinnedDestination
  | {
      readonly kind: "prohibited";
      readonly resolvedAddresses: readonly string[];
      readonly address: string;
      readonly category: TransportAddressCategory;
    }
  | { readonly kind: "dns-not-found"; readonly resolvedAddresses: readonly string[] }
  | { readonly kind: "dns-malformed"; readonly resolvedAddresses: readonly string[] };

export async function pinDestination(
  resolver: ResolverPort,
  hostname: string,
  signal: AbortSignal,
): Promise<PinResult> {
  const addresses = await resolveHostAddresses(resolver, hostname, signal);
  const resolvedAddresses = addresses.map(({ address }) => address);
  if (addresses.length === 0) return { kind: "dns-not-found", resolvedAddresses };
  if (hasMalformedAddress(addresses)) return { kind: "dns-malformed", resolvedAddresses };
  for (const answer of addresses) {
    const decision = classifyTransportAddress(answer.address);
    if (!decision.allowed) {
      return {
        kind: "prohibited",
        resolvedAddresses,
        address: answer.address,
        category: decision.category ?? "invalid",
      };
    }
  }
  return { kind: "pinned", resolvedAddresses, selected: addresses[0]! };
}

async function resolveHostAddresses(
  resolver: ResolverPort,
  hostname: string,
  signal: AbortSignal,
): Promise<readonly DnsAddress[]> {
  const family = isIP(hostname);
  if (family === 4 || family === 6) {
    return [{ address: hostname, family, ttlSeconds: 0 }];
  }
  return resolver.resolve({ hostname, signal });
}

function hasMalformedAddress(addresses: readonly DnsAddress[]): boolean {
  return addresses.some((answer) => {
    const family = isIP(answer.address);
    return (
      family !== answer.family ||
      (family !== 4 && family !== 6) ||
      !Number.isFinite(answer.ttlSeconds) ||
      answer.ttlSeconds < 0
    );
  });
}
