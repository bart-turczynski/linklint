/**
 * The single registry of shipped online reputation sources (LINK-angnbelm).
 *
 * Every cross-source gate — the M2 contract fan-in and the terms construction
 * gate — reads its cases from {@link ONLINE_SOURCE_REGISTRY} rather than from
 * its own hand-kept table. Before this existed, `reputation-sources-contract`
 * hard-coded exactly five descriptors, so a sixth source could ship, skip the
 * fan-in, and leave every cross-source assertion silently unchanged.
 *
 * Two things make an omission loud now:
 *
 * 1. {@link shippedDescriptorIds} reflects over the `./reputation` and
 *    `./mirrors` public barrels, and the fan-in gate fails NAMING THE ID if any
 *    exported descriptor is missing from this table. A source is not shippable
 *    without being registered.
 * 2. Each entry carries a real `construct(terms)` thunk, so the cross-source
 *    gates exercise the source's ACTUAL factory. Registering a source whose
 *    factory never runs the terms gate fails immediately.
 *
 * The accepted and refused terms are DERIVED from each descriptor, never
 * restated. A descriptor that later narrows `supportedModes` or starts
 * requiring attribution changes what these gates demand, with no edit here.
 */

import type { Enricher } from "linklint";

import {
  createPhishTankEnricher,
  createUrlhausEnricher,
  PHISHTANK_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_DESCRIPTOR,
} from "../../src/mirrors/index.js";
import {
  createDnsStateEnricher,
  createRdapAgeEnricher,
  createTlsCertificateEnricher,
  DNS_SOURCE_DESCRIPTOR,
  RDAP_SOURCE_DESCRIPTOR,
  TLS_SOURCE_DESCRIPTOR,
} from "../../src/reputation/index.js";
import type { DnsResolverPort } from "../../src/reputation/dns-types.js";
import type { RdapHttpClient } from "../../src/reputation/types.js";
import {
  assertValidSourceDescriptor,
  type CommercialMode,
  type OnlineSourceDescriptor,
  type SourceTermsAcceptance,
} from "../../src/sources/index.js";
import type { SafeTlsInspector } from "../../src/transport/index.js";

const ALL_COMMERCIAL_MODES: readonly CommercialMode[] = [
  "non-commercial",
  "fair-use",
  "commercial",
];

/**
 * Ports that reject on use. Construction must never touch them — a factory that
 * opened a socket or read a feed while being built would fail loudly here.
 */
const inertRdapClient: RdapHttpClient = {
  request: () => Promise.reject(new Error("registry fixture: no RDAP request expected")),
};
const inertTlsInspector: SafeTlsInspector = {
  inspect: () => Promise.reject(new Error("registry fixture: no TLS inspection expected")),
};
const inertDnsResolver: DnsResolverPort = {
  query: () => Promise.reject(new Error("registry fixture: no DNS query expected")),
  validateDnssec: () => Promise.reject(new Error("registry fixture: no DNSSEC query expected")),
};

/** A refused terms case, with the `OnlineSourceConfigError.code` it must carry. */
export interface RefusedTermsCase {
  readonly why: string;
  readonly terms: SourceTermsAcceptance;
  readonly code: "unsupported-commercial-mode" | "attribution-not-accepted";
}

export interface OnlineSourceRegistryEntry {
  readonly name: string;
  readonly descriptor: OnlineSourceDescriptor;
  /** A sample raw credential, present iff the descriptor demands one. */
  readonly sampleCredential?: string;
  /** Build the real enricher under `terms`; throws iff the terms gate refuses. */
  construct(terms: SourceTermsAcceptance): Enricher;
}

/**
 * Terms this descriptor's licence DOES grant: its first supported mode, plus
 * the attribution acknowledgement when it demands one.
 */
export function acceptedTermsFor(descriptor: OnlineSourceDescriptor): SourceTermsAcceptance {
  return {
    commercialMode: descriptor.terms.supportedModes[0]!,
    ...(descriptor.terms.attributionRequired ? { acceptAttribution: true } : {}),
  };
}

/**
 * Every terms value this descriptor's licence REFUSES. Empty for a source whose
 * terms grant all three modes and require no attribution — which is a fact about
 * that descriptor, not a gap in the gate.
 */
export function refusedTermsFor(
  descriptor: OnlineSourceDescriptor,
): readonly RefusedTermsCase[] {
  const cases: RefusedTermsCase[] = [];
  const granted = acceptedTermsFor(descriptor);

  for (const mode of ALL_COMMERCIAL_MODES) {
    if (descriptor.terms.supportedModes.includes(mode)) continue;
    cases.push({
      why: `commercial mode '${mode}' is outside the licence`,
      terms: { ...granted, commercialMode: mode },
      code: "unsupported-commercial-mode",
    });
  }

  if (descriptor.terms.attributionRequired) {
    cases.push({
      why: "attribution is required but explicitly declined",
      terms: { commercialMode: granted.commercialMode, acceptAttribution: false },
      code: "attribution-not-accepted",
    });
    cases.push({
      why: "attribution is required but not acknowledged at all",
      terms: { commercialMode: granted.commercialMode },
      code: "attribution-not-accepted",
    });
  }

  return cases;
}

/** Every shipped online reputation source, keyed to its real factory. */
export const ONLINE_SOURCE_REGISTRY: readonly OnlineSourceRegistryEntry[] = [
  {
    name: "RDAP",
    descriptor: RDAP_SOURCE_DESCRIPTOR,
    construct: (terms) => createRdapAgeEnricher({ terms, client: inertRdapClient, registry: null }),
  },
  {
    name: "TLS",
    descriptor: TLS_SOURCE_DESCRIPTOR,
    construct: (terms) => createTlsCertificateEnricher({ terms, inspector: inertTlsInspector }),
  },
  {
    name: "DNS",
    descriptor: DNS_SOURCE_DESCRIPTOR,
    construct: (terms) => createDnsStateEnricher({ terms, resolver: inertDnsResolver }),
  },
  {
    name: "URLhaus",
    descriptor: URLHAUS_SOURCE_DESCRIPTOR,
    sampleCredential: "urlhaus-auth-key-abc123",
    construct: (terms) => createUrlhausEnricher({ terms, resolveIndex: () => null }),
  },
  {
    name: "PhishTank",
    descriptor: PHISHTANK_SOURCE_DESCRIPTOR,
    sampleCredential: "phishtank-app-key-xyz789",
    construct: (terms) => createPhishTankEnricher({ terms, resolveIndex: () => null }),
  },
];

/** A barrel export that is structurally a valid source descriptor. */
function isSourceDescriptor(value: unknown): value is OnlineSourceDescriptor {
  if (typeof value !== "object" || value === null) return false;
  try {
    assertValidSourceDescriptor(value as OnlineSourceDescriptor);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ids of every descriptor the public `./reputation` and `./mirrors` barrels
 * export, discovered by reflection rather than listed. This is what turns a
 * sixth source into a loud failure instead of a silent omission.
 */
export function shippedDescriptorIds(
  barrels: readonly Record<string, unknown>[],
): readonly string[] {
  const ids = new Set<string>();
  for (const barrel of barrels) {
    for (const value of Object.values(barrel)) {
      if (isSourceDescriptor(value)) ids.add(value.id);
    }
  }
  return [...ids].sort();
}
