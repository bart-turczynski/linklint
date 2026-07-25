import { describe, expect, it } from "vitest";
import { classifyHost, ipClassification } from "../src/detectors/ip-classification.js";
import { inspect } from "../src/index.js";
import { analyzeIpv4, analyzeIpv6 } from "../src/parse/ip.js";
import {
  CLOUD_METADATA_ENDPOINTS,
  CLOUD_METADATA_VERSION,
} from "../src/data/cloud-metadata.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
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

    it("Oracle Cloud 192.0.0.192 is metadata, not an ordinary public address", () => {
      expect(classify("192.0.0.192")).toEqual(["ip_cloud_metadata"]);
      // Neighbours in 192.0.0.0/24 are NOT the endpoint — the table is a /32 set.
      expect(classify("192.0.0.193")).toEqual([]);
    });

    it("Alibaba 100.100.100.200 outranks the CGNAT reserved range (most specific)", () => {
      expect(classify("100.100.100.200")).toEqual(["ip_cloud_metadata"]);
      // The rest of 100.64/10 stays merely reserved.
      expect(classify("100.100.100.201")).toEqual(["ip_reserved"]);
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

    // Regression lock for the text-matching bug class: a prefix test on the
    // string "fd00:ec2:" blocks fd00:ec2::254 but lets fd00:0ec2::254 through,
    // though both spell the SAME 128 bits. Matching happens on the parsed
    // address, so every legal spelling of those bits must classify identically.
    it.each([
      "fd00:0ec2::254",
      "FD00:EC2::254",
      "fd00:ec2:0:0:0:0:0:254",
      "fd00:0ec2:0000:0000:0000:0000:0000:0254",
      "fd00:ec2::0254",
    ])("alternate spelling %s is the same endpoint (parsed, not text, comparison)", (spelling) => {
      expect(classify(spelling)).toEqual(["ip_cloud_metadata"]);
    });

    it("a NEIGHBOURING address that merely shares the text prefix is not metadata", () => {
      // fd00:ec2::255 differs in the low bits — private (fc00::/7), not metadata.
      expect(classify("fd00:ec2::255")).toEqual(["ip_private"]);
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

describe("cloud-metadata provider table", () => {
  const detailFor = (host: string): string =>
    ipClassification.run({ host } as InspectionContext)[0]?.detail ?? "";

  it("covers the documented provider set (no silent drift)", () => {
    expect(CLOUD_METADATA_ENDPOINTS.map((e) => e.address)).toEqual([
      "169.254.169.254",
      "fd00:ec2::254",
      "192.0.0.192",
      "100.100.100.200",
    ]);
  });

  // The classifier skips a row it cannot parse (importing the library must not
  // throw on a data typo), so parseability is asserted here instead — a typo
  // fails CI loudly rather than silently dropping an endpoint at runtime.
  it("every row parses as an IP and every row carries a provider + source", () => {
    for (const endpoint of CLOUD_METADATA_ENDPOINTS) {
      const parsed = analyzeIpv4(endpoint.address) ?? analyzeIpv6(endpoint.address);
      expect(parsed, `${endpoint.address} does not parse as an IP`).not.toBeNull();
      expect(endpoint.provider.length).toBeGreaterThan(0);
      expect(endpoint.source).toMatch(/^https:\/\//);
    }
  });

  it("every row classifies as ip_cloud_metadata and reports its provider", () => {
    for (const endpoint of CLOUD_METADATA_ENDPOINTS) {
      const c = classifyHost(endpoint.address);
      expect(c?.bucket, `${endpoint.address}`).toBe("ip_cloud_metadata");
      expect(c?.provider).toBe(endpoint.provider);
    }
  });

  it.each([
    { host: "169.254.169.254", provider: "AWS / Azure / GCP / DigitalOcean / OpenStack" },
    { host: "fd00:ec2::254", provider: "AWS (IPv6 IMDS)" },
    { host: "192.0.0.192", provider: "Oracle Cloud" },
    { host: "100.100.100.200", provider: "Alibaba Cloud" },
  ])("detail for $host names the provider ($provider)", ({ host, provider }) => {
    const detail = detailFor(host);
    expect(detail).toContain(provider);
    expect(detail).toContain("instance-metadata endpoint");
  });

  it("a generic range bucket keeps its provider-free wording", () => {
    const c = classifyHost("169.254.10.20");
    expect(c?.bucket).toBe("ip_link_local");
    expect(c?.provider).toBeUndefined();
    expect(detailFor("169.254.10.20")).toContain("a link-local address");
  });

  // The table is vendor-documented, not IANA-derived, so it carries its own
  // provenance stamp — independent of any registry pin.
  it("is version-stamped separately in dataVersions", () => {
    expect(DATA_VERSIONS.cloudMetadata).toBe(CLOUD_METADATA_VERSION);
    expect(DATA_VERSIONS.cloudMetadata).not.toBe(DATA_VERSIONS.publicSuffixList);
    expect(inspect("http://192.0.0.192/").dataVersions.cloudMetadata).toBe(CLOUD_METADATA_VERSION);
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

  it("escalates the non-AWS provider endpoints too (table drives both detectors)", () => {
    expect(codes("http://192.0.0.192/latest/", { agentMode: true })).toContain(
      "ssrf_cloud_metadata",
    );
    expect(codes("http://100.100.100.200/latest/meta-data/", { agentMode: true })).toContain(
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
