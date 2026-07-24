/**
 * M10 U1 — cross-source descriptor contract fan-in (LINK-lbhcpjkj).
 *
 * This is the single place that proves EVERY shipped online reputation source
 * satisfies the M2 online-source contract. Each source's own suite still calls
 * {@link assertOnlineSourceContract} in isolation; the value of this file is the
 * fan-in: all five real descriptors are enumerated in one table and run through
 * the same 8-criteria kit here, closing the gap where a source (notably RDAP)
 * had never been driven through the FULL kit. If a sixth reputation source ships
 * without an entry in `SOURCES` below, its absence is a visible omission in this
 * cross-source gate rather than a silent one.
 *
 * Fan-in only: this file asserts the CONTRACT for each descriptor and nothing
 * about any source's internal behavior (findings, evidence payloads, lookups) —
 * those belong to each source's own suite.
 */

import { describe, expect, it } from "vitest";

import {
  DNS_SOURCE_DESCRIPTOR,
  RDAP_SOURCE_DESCRIPTOR,
  TLS_SOURCE_DESCRIPTOR,
} from "../../src/reputation/index.js";
import {
  PHISHTANK_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_DESCRIPTOR,
} from "../../src/mirrors/index.js";
import type { OnlineSourceDescriptor } from "../../src/sources/index.js";
import {
  assertOnlineSourceContract,
  type OnlineSourceContractOptions,
} from "./online-source-contract-kit.js";

interface ContractCase {
  readonly name: string;
  readonly descriptor: OnlineSourceDescriptor;
  /** Per-source kit options; omitted (`{}`) for no-credential sources. */
  readonly options: OnlineSourceContractOptions;
}

/**
 * Every shipped online reputation source, with the kit options that source
 * requires. Evidence-only live providers (RDAP/TLS/DNS) take no credential;
 * the caller-owned BYOK mirrors (URLhaus/PhishTank) supply a sample credential.
 */
const SOURCES: readonly ContractCase[] = [
  { name: "RDAP", descriptor: RDAP_SOURCE_DESCRIPTOR, options: {} },
  { name: "TLS", descriptor: TLS_SOURCE_DESCRIPTOR, options: {} },
  { name: "DNS", descriptor: DNS_SOURCE_DESCRIPTOR, options: {} },
  {
    name: "URLhaus",
    descriptor: URLHAUS_SOURCE_DESCRIPTOR,
    options: { sampleCredential: "urlhaus-auth-key-abc123" },
  },
  {
    name: "PhishTank",
    descriptor: PHISHTANK_SOURCE_DESCRIPTOR,
    options: { sampleCredential: "phishtank-app-key-xyz789" },
  },
];

describe("reputation sources — cross-source M2 contract fan-in", () => {
  it("enumerates every shipped reputation source (a sixth is a visible omission)", () => {
    expect(SOURCES).toHaveLength(5);
    expect(SOURCES.map((source) => source.descriptor.id)).toEqual([
      RDAP_SOURCE_DESCRIPTOR.id,
      TLS_SOURCE_DESCRIPTOR.id,
      DNS_SOURCE_DESCRIPTOR.id,
      URLHAUS_SOURCE_DESCRIPTOR.id,
      PHISHTANK_SOURCE_DESCRIPTOR.id,
    ]);
  });

  it.each(SOURCES)("$name satisfies the shared online-source contract", ({ descriptor, options }) => {
    assertOnlineSourceContract(descriptor, options);
  });
});
