/**
 * M10 U1 — cross-source descriptor contract fan-in (LINK-lbhcpjkj, LINK-angnbelm).
 *
 * This is the single place that proves EVERY shipped online reputation source
 * satisfies the M2 online-source contract. Each source's own suite still calls
 * {@link assertOnlineSourceContract} in isolation; the value of this file is the
 * fan-in: every real descriptor runs through the same 8-criteria kit here,
 * closing the gap where a source (notably RDAP) had never been driven through
 * the FULL kit.
 *
 * The table is no longer written here. It comes from
 * {@link ONLINE_SOURCE_REGISTRY} (LINK-angnbelm), and the first assertion below
 * reflects over the public `./reputation` and `./mirrors` barrels to prove the
 * registry covers every descriptor those barrels export. A sixth source that
 * ships without being registered fails HERE, by id, instead of leaving this
 * gate quietly measuring five things forever.
 *
 * Fan-in only: this file asserts the CONTRACT for each descriptor and nothing
 * about any source's internal behavior (findings, evidence payloads, lookups) —
 * those belong to each source's own suite.
 */

import { describe, expect, it } from "vitest";

import * as mirrors from "../../src/mirrors/index.js";
import * as reputation from "../../src/reputation/index.js";
import {
  assertOnlineSourceContract,
  type OnlineSourceContractOptions,
} from "./online-source-contract-kit.js";
import { ONLINE_SOURCE_REGISTRY, shippedDescriptorIds } from "./online-source-registry.js";

/** Kit options are derived from the registry entry, never restated per source. */
function kitOptions(sampleCredential: string | undefined): OnlineSourceContractOptions {
  return sampleCredential === undefined ? {} : { sampleCredential };
}

describe("reputation sources — cross-source M2 contract fan-in", () => {
  it("covers every source descriptor the public barrels export", () => {
    const registered = [...ONLINE_SOURCE_REGISTRY.map((source) => source.descriptor.id)].sort();
    const shipped = shippedDescriptorIds([reputation, mirrors]);

    // Named-difference assertions, so a failure says WHICH source is missing.
    expect(shipped.filter((id) => !registered.includes(id))).toEqual([]);
    expect(registered.filter((id) => !shipped.includes(id))).toEqual([]);
    expect(ONLINE_SOURCE_REGISTRY.length).toBeGreaterThan(0);
  });

  it.each(ONLINE_SOURCE_REGISTRY)(
    "$name satisfies the shared online-source contract",
    ({ descriptor, sampleCredential }) => {
      assertOnlineSourceContract(descriptor, kitOptions(sampleCredential));
    },
  );
});
