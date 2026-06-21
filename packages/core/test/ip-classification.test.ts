import { describe, expect, it } from "vitest";
import { ipClassification } from "../src/detectors/ip-classification.js";
import type { InspectionContext } from "../src/detectors/types.js";

// The literal-IP range classifier reads only `ctx.host` (the IP literal, IPv6
// with brackets already stripped), like its sibling ip_obfuscation. A minimal
// host-only context exercises the bucket logic directly.
function classify(host: string): string[] {
  const findings = ipClassification.run({ host } as InspectionContext);
  return findings.map((f) => f.code);
}

describe("ip_classification — literal-IP range buckets", () => {
  it("empty host yields nothing", () => {
    expect(classify("")).toEqual([]);
  });

  it("emits at most one bucket per address", () => {
    for (const h of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"]) {
      expect(classify(h).length).toBe(1);
    }
  });

  describe("IPv4", () => {
    it("loopback: 127.0.0.0/8", () => {
      expect(classify("127.0.0.1")).toEqual(["ip_loopback"]);
      expect(classify("127.255.255.254")).toEqual(["ip_loopback"]);
    });

    it("private: RFC 1918 ranges", () => {
      expect(classify("10.0.0.1")).toEqual(["ip_private"]);
      expect(classify("172.16.0.1")).toEqual(["ip_private"]);
      expect(classify("172.31.255.255")).toEqual(["ip_private"]);
      expect(classify("192.168.1.1")).toEqual(["ip_private"]);
    });

    it("172.x outside 16-31 is NOT private (reserved-or-public boundary)", () => {
      // 172.15 and 172.32 are public — neither private nor any other bucket.
      expect(classify("172.15.0.1")).toEqual([]);
      expect(classify("172.32.0.1")).toEqual([]);
    });

    it("link-local: 169.254.0.0/16", () => {
      expect(classify("169.254.0.1")).toEqual(["ip_link_local"]);
      expect(classify("169.254.255.255")).toEqual(["ip_link_local"]);
    });

    it("cloud-metadata endpoint outranks link-local (most specific)", () => {
      expect(classify("169.254.169.254")).toEqual(["ip_cloud_metadata"]);
    });

    it("reserved: 0/8, CGNAT 100.64/10, multicast, 240/4", () => {
      expect(classify("0.0.0.0")).toEqual(["ip_reserved"]);
      expect(classify("100.64.0.1")).toEqual(["ip_reserved"]);
      expect(classify("224.0.0.1")).toEqual(["ip_reserved"]);
      expect(classify("240.0.0.1")).toEqual(["ip_reserved"]);
    });

    it("ordinary public IPv4 yields no bucket", () => {
      expect(classify("8.8.8.8")).toEqual([]);
      expect(classify("93.184.216.34")).toEqual([]);
    });

    it("classifies obfuscated IPv4 by its decoded canonical form", () => {
      // 2130706433 == 127.0.0.1; the classifier runs on canonical, obfuscated or not.
      expect(classify("2130706433")).toEqual(["ip_loopback"]);
      expect(classify("0x7f000001")).toEqual(["ip_loopback"]);
    });
  });

  describe("IPv6", () => {
    it("loopback: ::1", () => {
      expect(classify("::1")).toEqual(["ip_loopback"]);
    });

    it("private: fc00::/7 (fc.. and fd..)", () => {
      expect(classify("fc00::1")).toEqual(["ip_private"]);
      expect(classify("fdff::1")).toEqual(["ip_private"]);
    });

    it("link-local: fe80::/10", () => {
      expect(classify("fe80::1")).toEqual(["ip_link_local"]);
      expect(classify("febf::1")).toEqual(["ip_link_local"]);
    });

    it("cloud-metadata IPv6 endpoint outranks fc00::/7", () => {
      expect(classify("fd00:ec2::254")).toEqual(["ip_cloud_metadata"]);
    });

    it("reserved: unspecified :: and multicast ff00::/8", () => {
      expect(classify("::")).toEqual(["ip_reserved"]);
      expect(classify("ff02::1")).toEqual(["ip_reserved"]);
    });

    it("ordinary public/documentation IPv6 yields no bucket", () => {
      expect(classify("2001:db8::1")).toEqual([]);
    });
  });

  describe("IPv4-in-IPv6 embedding classified by the embedded v4", () => {
    it("::ffff:127.0.0.1 -> loopback", () => {
      expect(classify("::ffff:127.0.0.1")).toEqual(["ip_loopback"]);
    });

    it("::ffff:169.254.169.254 -> cloud_metadata (most specific)", () => {
      expect(classify("::ffff:169.254.169.254")).toEqual(["ip_cloud_metadata"]);
    });

    it("::ffff:10.0.0.1 -> private", () => {
      expect(classify("::ffff:10.0.0.1")).toEqual(["ip_private"]);
    });
  });

  it("detail names the bucket meaning and the canonical address", () => {
    const [f] = ipClassification.run({ host: "169.254.169.254" } as InspectionContext);
    expect(f?.code).toBe("ip_cloud_metadata");
    expect(f?.detail).toContain("169.254.169.254");
    expect(f?.detail).toContain("metadata");
  });
});
