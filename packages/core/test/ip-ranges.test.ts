import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  IPV4_RANGES,
  IPV6_RANGES,
  IP_RANGES_VERSION,
  matchIpv4Range,
  matchIpv6Range,
} from "../src/data/ip-ranges.js";
import { IPV4_SPECIAL_RANGES, IPV6_SPECIAL_RANGES } from "../src/data/ip-ranges.generated.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { classifyHost } from "../src/detectors/ip-classification.js";

// Paths resolved relative to THIS module (not process.cwd()) so the test runs
// the same from any working directory.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const GENERATOR = join(REPO_ROOT, "tools", "build-ip-ranges.mjs");
const ARTIFACT = join(REPO_ROOT, "packages", "core", "src", "data", "ip-ranges.generated.ts");
const SNAPSHOTS = [
  join(REPO_ROOT, "tools", "data", "iana-ipv4-special-registry-1.csv"),
  join(REPO_ROOT, "tools", "data", "iana-ipv6-special-registry-1.csv"),
];

/** Dotted quad → uint32, matching the classifier's own conversion. */
function u32(dotted: string): number {
  return dotted.split(".").reduce((n, o) => n * 256 + Number(o), 0) >>> 0;
}

/** Expand a fully-written IPv6 (no `::`) into hextets. */
function hextets(addr: string): number[] {
  return addr.split(":").map((h) => parseInt(h, 16));
}

describe("ip-ranges.generated.ts is reproducible from the committed registries", () => {
  // build-confusables.mjs has a --check mode that nothing runs, so its artifact
  // can drift silently. This closes that gap for the IP ranges: the two IANA
  // CSVs are committed under tools/data/, so regeneration is byte-reproducible
  // OFFLINE and drift fails CI instead of being discovered in production.
  // Explicit timeout for the same reason as confusables-drift.test.ts — see the
  // note there (LINK-hhzehdsm). Any test that spawns a subprocess is timed
  // against machine load rather than its own work, so the 5000 ms default is the
  // wrong budget even though this one costs ~60 ms idle.
  it(
    "--check passes: re-rendering the committed CSVs reproduces the artifact",
    () => {
      expect(() => execFileSync(process.execPath, [GENERATOR, "--check"], { stdio: "pipe" })).not.toThrow();
    },
    60_000,
  );

  it("the committed snapshots exist and are the parsed inputs (sha256 recorded)", () => {
    const artifact = readFileSync(ARTIFACT, "utf8");
    for (const snapshot of SNAPSHOTS) {
      expect(statSync(snapshot).size).toBeGreaterThan(0);
    }
    // Both source URLs and both digests are carried in the header.
    expect(artifact).toContain("iana-ipv4-special-registry-1.csv");
    expect(artifact).toContain("iana-ipv6-special-registry-1.csv");
    expect(artifact.match(/^\/\/\s+sha256: [0-9a-f]{64}/gm)?.length).toBe(2);
  });

  it("is version-stamped in dataVersions, independent of the vendor tables", () => {
    expect(DATA_VERSIONS.ipRanges).toBe(IP_RANGES_VERSION);
    expect(DATA_VERSIONS.ipRanges).not.toBe(DATA_VERSIONS.cloudMetadata);
    expect(IP_RANGES_VERSION).toMatch(/^iana-special-purpose-\d{4}-\d{2}-\d{2}$/);
  });
});

describe("table integrity", () => {
  it("carries the registry rows plus exactly one multicast overlay per family", () => {
    expect(IPV4_SPECIAL_RANGES.length).toBeGreaterThan(20);
    expect(IPV6_SPECIAL_RANGES.length).toBeGreaterThan(20);
    expect(IPV4_RANGES.length).toBe(IPV4_SPECIAL_RANGES.length + 1);
    expect(IPV6_RANGES.length).toBe(IPV6_SPECIAL_RANGES.length + 1);
  });

  it("is sorted by DESCENDING prefix length (the linear scan IS the LPM)", () => {
    for (const table of [IPV4_RANGES, IPV6_RANGES]) {
      for (let i = 1; i < table.length; i++) {
        expect(table[i]!.prefix).toBeLessThanOrEqual(table[i - 1]!.prefix);
      }
    }
  });

  it("every row is prefix-aligned, cited, and in range", () => {
    for (const row of IPV4_RANGES) {
      expect(row.prefix, `${row.name}`).toBeGreaterThan(0);
      expect(row.prefix).toBeLessThanOrEqual(32);
      expect(((row.base >>> (32 - row.prefix)) << (32 - row.prefix)) >>> 0).toBe(row.base);
      expect(row.rfc, `${row.name}`).toMatch(/RFC/);
    }
    for (const row of IPV6_RANGES) {
      expect(row.base.length).toBe(8);
      expect(row.prefix, `${row.name}`).toBeGreaterThan(0);
      expect(row.prefix).toBeLessThanOrEqual(128);
      expect(row.rfc, `${row.name}`).toMatch(/RFC/);
      for (const h of row.base) expect(h).toBeLessThanOrEqual(0xffff);
    }
  });

  it("footnote markers are stripped from the parsed fields", () => {
    for (const row of [...IPV4_RANGES, ...IPV6_RANGES]) {
      expect(row.name).not.toMatch(/\[\d+\]/);
      expect(row.rfc).not.toMatch(/\[\d+\]/);
    }
  });

  it("the multiline quoted CSV fields survived the parse", () => {
    // 255.255.255.255/32's citation spans two physical lines in the CSV
    // ("[RFC8190]\n        [RFC919], Section 7"); a line-splitting parser would
    // have truncated or dropped it.
    const broadcast = IPV4_RANGES.find((r) => r.base === 0xffffffff && r.prefix === 32);
    expect(broadcast?.name).toBe("Limited Broadcast");
    expect(broadcast?.rfc).toBe("[RFC8190] [RFC919], Section 7");
    // fc00::/7 likewise ("[RFC4193]\n        [RFC8190]").
    const ula = IPV6_RANGES.find((r) => r.prefix === 7);
    expect(ula?.rfc).toBe("[RFC4193] [RFC8190]");
  });

  it("the multi-block cell '192.0.0.170/32, 192.0.0.171/32' became TWO rows", () => {
    for (const dotted of ["192.0.0.170", "192.0.0.171"]) {
      const row = IPV4_RANGES.find((r) => r.base === u32(dotted) && r.prefix === 32);
      expect(row?.name, dotted).toBe("NAT64/DNS64 Discovery");
    }
  });
});

describe("longest-prefix-match", () => {
  it("returns the MOST specific match, not the first listed", () => {
    // 192.0.0.8/32 (dummy address) sits inside 192.0.0.0/29, inside
    // 192.0.0.0/24 — three nested rows, one answer.
    expect(matchIpv4Range(u32("192.0.0.8"))?.name).toBe("IPv4 dummy address");
    expect(matchIpv4Range(u32("192.0.0.20"))?.name).toBe("IETF Protocol Assignments");
    expect(matchIpv4Range(u32("192.0.0.1"))?.name).toBe("IPv4 Service Continuity Prefix");
  });

  it("a null-bucket carve-out STOPS the search (does not fall through to its parent)", () => {
    expect(matchIpv4Range(u32("192.0.0.9"))).toBeNull();
    expect(matchIpv4Range(u32("192.0.0.10"))).toBeNull();
    expect(matchIpv4Range(u32("192.0.0.11"))?.bucket).toBe("ip_reserved");
    expect(matchIpv6Range(hextets("2001:1:0:0:0:0:0:1"))).toBeNull();
    expect(matchIpv6Range(hextets("2001:1:0:0:0:0:0:9"))?.bucket).toBe("ip_reserved");
  });

  it("ordinary public addresses match nothing", () => {
    expect(matchIpv4Range(u32("8.8.8.8"))).toBeNull();
    expect(matchIpv4Range(u32("93.184.216.34"))).toBeNull();
    expect(matchIpv6Range(hextets("2606:4700:4700:0:0:0:0:1111"))).toBeNull();
  });

  it("rejects a malformed hextet vector rather than guessing", () => {
    expect(matchIpv6Range([0xfe80, 0, 0])).toBeNull();
  });
});

describe("non-registry overlays still win by most-specific match", () => {
  // Multicast is NOT in the special-purpose registries (grep '^224\.' and
  // '^ff00' both return zero rows) — it lives in the separate IANA Multicast
  // Address Space registries. A purely registry-derived table would have LOST
  // these, and the corpus pins both.
  it("multicast is preserved by the explicit overlay", () => {
    expect(classifyHost("224.0.0.1")?.bucket).toBe("ip_reserved");
    expect(classifyHost("239.0.0.1")?.bucket).toBe("ip_reserved");
    expect(classifyHost("ff00::1")?.bucket).toBe("ip_reserved");
    expect(classifyHost("ff02::1")?.bucket).toBe("ip_reserved");
    // The neighbouring future-use block is registry-derived and unaffected.
    expect(classifyHost("240.0.0.1")?.rangeName).toBe("Reserved");
  });

  it("the cloud-metadata table outranks the registry range enclosing it", () => {
    // 192.0.0.192 inside 192.0.0.0/24, 100.100.100.200 inside 100.64.0.0/10,
    // 169.254.169.254 inside 169.254.0.0/16 — all reserved-or-link-local ranges.
    for (const host of ["192.0.0.192", "100.100.100.200", "169.254.169.254"]) {
      expect(classifyHost(host)?.bucket, host).toBe("ip_cloud_metadata");
    }
    // …and their neighbours fall back to the enclosing registry range.
    expect(classifyHost("192.0.0.193")?.bucket).toBe("ip_reserved");
    expect(classifyHost("100.100.100.201")?.bucket).toBe("ip_reserved");
    expect(classifyHost("169.254.169.253")?.bucket).toBe("ip_link_local");
  });
});

describe("curated NO-BUCKET classes (registry rows that deliberately earn nothing)", () => {
  // Documentation prefixes are inert: not an SSRF target, not deception. The
  // corpus pins https://[2001:db8::1]/ at score exactly 0.
  it("documentation prefixes stay unclassified", () => {
    for (const host of ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "3fff::1"]) {
      expect(classifyHost(host), host).toBeNull();
    }
  });

  // Transition prefixes are routing envelopes, not destination classes: what
  // matters is the IPv4 inside them (parse/ip.ts recovers it for the low-32
  // wrappers). Bucketing the envelope would flag NAT64 doing its ordinary job.
  it("transition wrapper prefixes stay unclassified", () => {
    for (const host of [
      "::ffff:808:808", // IPv4-mapped 8.8.8.8
      "64:ff9b::808:808", // NAT64 well-known prefix, public target
      "64:ff9b:1::808:808", // RFC 8215 local-use NAT64, public target (unwrapped, no bucket)
      "2002:a9fe:a9fe::", // 6to4 (not unwrapped)
      "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo (not unwrapped)
    ]) {
      expect(classifyHost(host), host).toBeNull();
    }
  });

  it("globally reachable registry blocks stay unclassified", () => {
    for (const host of ["192.31.196.1", "192.175.48.1", "2001:20::1", "2620:4f:8000::1"]) {
      expect(classifyHost(host), host).toBeNull();
    }
  });
});
