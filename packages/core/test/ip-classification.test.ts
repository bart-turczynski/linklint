import { describe, expect, it } from "vitest";
import { ipClassification } from "../src/detectors/ip-classification.js";
import { inspect } from "../src/index.js";
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

describe("ip_cloud_metadata scoring + agentMode SSRF escalation (ssrf_cloud_metadata)", () => {
  const codes = (url: string, opts?: Parameters<typeof inspect>[1]) =>
    inspect(url, opts).reasons.map((r) => r.code);

  it("lands high (0.75) by default — blocks the --fail-on high gate, not critical", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/");
    expect(r.reasons.map((x) => x.code)).toContain("ip_cloud_metadata");
    expect(r.severity).toBe("high");
    const reason = r.reasons.find((x) => x.code === "ip_cloud_metadata")!;
    expect(reason.weight).toBeCloseTo(0.75, 5);
  });

  it("does NOT emit the agent-gated ssrf_cloud_metadata in the default verdict", () => {
    expect(codes("http://169.254.169.254/")).not.toContain("ssrf_cloud_metadata");
  });

  it("escalates to critical under agentMode — ip_cloud_metadata + ssrf_cloud_metadata blocker", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/", { agentMode: true });
    const c = r.reasons.map((x) => x.code);
    expect(c).toContain("ip_cloud_metadata");
    expect(c).toContain("ssrf_cloud_metadata");
    expect(r.severity).toBe("critical");
    const blocker = r.reasons.find((x) => x.code === "ssrf_cloud_metadata")!;
    expect(blocker.weight).toBe(1);
  });

  it("escalates the IPv6 and v4-in-v6 metadata forms too", () => {
    expect(codes("https://[fd00:ec2::254]/", { agentMode: true })).toContain("ssrf_cloud_metadata");
    expect(codes("https://[::ffff:169.254.169.254]/", { agentMode: true })).toContain(
      "ssrf_cloud_metadata",
    );
  });

  it("does NOT escalate the generic internal buckets under agentMode (loopback stays low)", () => {
    const r = inspect("http://127.0.0.1:3000/", { agentMode: true });
    expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
    expect(r.severity).toBe("low");
  });

  it("does NOT fire on a public IP", () => {
    expect(codes("http://93.184.216.34/", { agentMode: true })).not.toContain("ssrf_cloud_metadata");
  });
});
