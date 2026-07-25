import { describe, expect, it } from "vitest";

import { classifyHost } from "linklint";

import { classifyTransportAddress, SUPPLEMENTAL_RANGES } from "../src/transport/address.js";

/**
 * LINK-cmstadju — drift guard between core's IANA-derived range table and this
 * package's supplemental table.
 *
 * The hazard is not overlap, it is SILENT overlap: two independently-maintained
 * definitions of "non-global address" with nothing asserting they still agree.
 * `classifyTransportAddress` asks core first and falls through to the
 * supplemental rules, so when core's coverage grows a supplemental rule quietly
 * stops being reachable and its category stops being produced — which already
 * happened once, when S3 moved 198.18.0.1 from `benchmark` to `ip_reserved`.
 *
 * These tests pin WHICH LAYER answers for every supplemental range. A rule that
 * becomes shadowed, or un-shadowed, fails here instead of silently changing what
 * callers observe.
 *
 * The tests read `SUPPLEMENTAL_RANGES` itself. A copy of the range list would be
 * a third independent definition and would guard nothing.
 */

/** Which layer produced the decision. */
type Layer = "core" | "supplemental";

interface Probe {
  /** `network/prefix` of the supplemental range this probe belongs to. */
  readonly range: string;
  readonly address: string;
  readonly layer: Layer;
  readonly category: string;
  readonly why?: string;
}

const PROBES: readonly Probe[] = [
  // ── Live: core deliberately leaves documentation prefixes unclassified ────
  { range: "192.0.2.0/24", address: "192.0.2.1", layer: "supplemental", category: "documentation" },
  { range: "198.51.100.0/24", address: "198.51.100.42", layer: "supplemental", category: "documentation" },
  { range: "203.0.113.0/24", address: "203.0.113.9", layer: "supplemental", category: "documentation" },
  { range: "2001:db8::/32", address: "2001:db8::1", layer: "supplemental", category: "documentation" },
  { range: "3fff::/20", address: "3fff:1::1", layer: "supplemental", category: "documentation" },

  // ── Shadowed: core's IANA table answers first, so the supplemental category
  //    is currently unreachable. Blocked either way; only the label differs.
  {
    range: "198.18.0.0/15",
    address: "198.18.0.1",
    layer: "core",
    category: "ip_reserved",
    why: "IANA Benchmarking, Globally Reachable = False (S3)",
  },
  { range: "2001:2::/48", address: "2001:2::1", layer: "core", category: "ip_reserved" },
  { range: "192.0.0.0/24", address: "192.0.0.1", layer: "core", category: "ip_reserved" },
  { range: "192.88.99.0/24", address: "192.88.99.1", layer: "core", category: "ip_reserved" },
  { range: "100::/64", address: "100::1", layer: "core", category: "ip_reserved" },
  { range: "5f00::/16", address: "5f00:1::1", layer: "core", category: "ip_reserved" },

  // ── Live: a transition wrapper around a PUBLIC IPv4. Core unwraps it and
  //    correctly declines to bucket NAT64 doing its ordinary job, so the
  //    supplemental rule is what stops the connection.
  {
    range: "64:ff9b::/96",
    address: "64:ff9b::808:808",
    layer: "supplemental",
    category: "transition",
    why: "NAT64 well-known prefix wrapping public 8.8.8.8 — no core bucket by design",
  },
  {
    range: "64:ff9b:1::/48",
    address: "64:ff9b:1::808:808",
    layer: "supplemental",
    category: "transition",
    why: "RFC 8215 local-use NAT64 wrapping 8.8.8.8 (LINK-evooubiz)",
  },
  { range: "::/96", address: "::808:808", layer: "supplemental", category: "transition" },

  // ── Live: 6to4 and Teredo carry no core bucket BY DECISION (LINK-evooubiz).
  //    Declining to score them is not declining to block them.
  {
    range: "2001::/23",
    address: "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    layer: "supplemental",
    category: "transition",
    why: "Teredo — core gives no bucket, the boundary still refuses to connect",
  },
  {
    range: "2002::/16",
    address: "2002:a9fe:a9fe::",
    layer: "supplemental",
    category: "transition",
    why: "6to4 embedding a link-local gateway — no core bucket by decision",
  },

  { range: "::ffff:0:0/96", address: "::ffff:808:808", layer: "supplemental", category: "ip_reserved" },
  {
    range: "fec0::/10",
    address: "fec0::1",
    layer: "supplemental",
    category: "ip_reserved",
    why: "deprecated site-local (RFC 3879) — IANA removed it, so core has no row",
  },
];

const key = (r: { network: string; prefix: number }): string => `${r.network}/${r.prefix}`;

describe("LINK-cmstadju — core / supplemental range table consistency", () => {
  it("every supplemental range carries at least one probe", () => {
    // Structural: adding a rule without pinning which layer answers for it would
    // reintroduce exactly the blind spot this guard exists to close.
    const probed = new Set(PROBES.map((p) => p.range));
    const declared = SUPPLEMENTAL_RANGES.map(key);
    for (const range of declared) {
      expect(probed.has(range), `no probe for supplemental range ${range}`).toBe(true);
    }
    // And no probe may name a range that no longer exists.
    for (const range of probed) {
      expect(declared, `probe names unknown range ${range}`).toContain(range);
    }
  });

  it("pins which layer answers for each supplemental range", () => {
    for (const probe of PROBES) {
      const core = classifyHost(probe.address);
      const actualLayer: Layer = core === null ? "supplemental" : "core";
      const label = `${probe.address} (${probe.range})${probe.why ? ` — ${probe.why}` : ""}`;
      expect(actualLayer, label).toBe(probe.layer);
      expect(classifyTransportAddress(probe.address).category, label).toBe(probe.category);
    }
  });

  it("INVARIANT — every probed address is blocked, whichever layer answers", () => {
    // The safety property. Which table matched is an implementation detail; that
    // nothing here is connectable is not.
    for (const probe of PROBES) {
      const decision = classifyTransportAddress(probe.address);
      expect(decision.allowed, probe.address).toBe(false);
      expect(decision.category, probe.address).not.toBeNull();
    }
  });

  it("the documentation asymmetry is deliberate and still holds", () => {
    // Core must NOT classify documentation prefixes — they are inert examples,
    // not deception, and scoring them would be a false positive. Online must
    // still refuse to connect. If core ever starts bucketing these, the
    // supplemental rules above go shadowed and the layer pin catches it, but
    // state the underlying property directly too.
    for (const address of ["192.0.2.1", "198.51.100.42", "203.0.113.9", "2001:db8::1", "3fff:1::1"]) {
      expect(classifyHost(address), address).toBeNull();
      expect(classifyTransportAddress(address).allowed, address).toBe(false);
    }
  });

  it("a genuinely global address is still allowed through both layers", () => {
    // The other direction: the backstop must not have grown teeth it should not
    // have. If either table starts swallowing public space this fails.
    for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
      const decision = classifyTransportAddress(address);
      expect(decision.allowed, address).toBe(true);
      expect(decision.category, address).toBeNull();
    }
  });
});
