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
      // Neighbours in 192.0.0.0/24 are NOT the endpoint — the metadata table is
      // a /32 set. S3 moved them from [] to ip_reserved: 192.0.0.0/24 is the
      // IANA "IETF Protocol Assignments" block (Globally Reachable = False), so
      // under the registry table the neighbour is reserved, and the /32 overlay
      // is what keeps .192 itself metadata.
      expect(classify("192.0.0.193")).toEqual(["ip_reserved"]);
    });

    // S3 — the whole reason the table is longest-prefix-match rather than a flat
    // first-match list. The registry marks 192.0.0.9/32 (PCP anycast) and
    // 192.0.0.10/32 (TURN anycast) Globally Reachable = True INSIDE the
    // non-global 192.0.0.0/24. A flat list either loses the /24 or loses the
    // /32; only the longest match can express the carve-out.
    it("S3 globally-reachable /32 carve-outs beat the enclosing reserved /24", () => {
      expect(classify("192.0.0.9")).toEqual([]);
      expect(classify("192.0.0.10")).toEqual([]);
      // …while the rest of the same /24 stays reserved, including its own
      // neighbours on either side of the carve-outs.
      expect(classify("192.0.0.8")).toEqual(["ip_reserved"]);
      expect(classify("192.0.0.11")).toEqual(["ip_reserved"]);
      expect(classify("192.0.0.1")).toEqual(["ip_reserved"]);
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

    // S3 — the IPv6 half of the same carve-out: 2001:1::1/128 and 2001:1::2/128
    // are Globally Reachable = True inside 2001::/23 (IETF Protocol
    // Assignments, not globally reachable). The old first-hextet test could not
    // express a /23 at all, let alone a /128 exception inside it.
    it("S3 globally-reachable /128 carve-outs beat the enclosing 2001::/23", () => {
      expect(classify("2001:1::1")).toEqual([]);
      expect(classify("2001:1::2")).toEqual([]);
      expect(classify("2001:1::4")).toEqual(["ip_reserved"]);
      expect(classify("2001:100::1")).toEqual(["ip_reserved"]);
    });

    // S3 — sub-hextet prefixes the old first-hextet comparison rounded off.
    it("S3 matches on the exact prefix boundary, not on whole hextets", () => {
      // fc00::/7 ends at fdff:…; fe00:: is OUTSIDE it and inside nothing else.
      expect(classify("fdff:ffff::1")).toEqual(["ip_private"]);
      expect(classify("fe00::1")).toEqual([]);
      // fe80::/10 ends at febf:…; fec0:: was site-local, deprecated and NOT in
      // the registry, so it is unclassified.
      expect(classify("febf:ffff::1")).toEqual(["ip_link_local"]);
      expect(classify("fec0::1")).toEqual([]);
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

    // S1 — the bucket follows the BITS, not the spelling. Before this, only the
    // dotted-quad spelling was recognized, so `[64:ff9b::a9fe:a9fe]` scored 0.
    it("S1 every low-32 wrapper prefix classifies like its dotted-quad spelling", () => {
      const pairs: Array<[string, string, string]> = [
        // [hex spelling, dotted spelling, expected bucket]
        ["::ffff:a9fe:a9fe", "::ffff:169.254.169.254", "ip_cloud_metadata"],
        ["64:ff9b::a9fe:a9fe", "64:ff9b::169.254.169.254", "ip_cloud_metadata"],
        ["::a9fe:a9fe", "::169.254.169.254", "ip_cloud_metadata"],
        ["::ffff:7f00:1", "::ffff:127.0.0.1", "ip_loopback"],
        ["64:ff9b::7f00:1", "64:ff9b::127.0.0.1", "ip_loopback"],
        ["::7f00:1", "::127.0.0.1", "ip_loopback"],
        ["64:ff9b::a00:1", "64:ff9b::10.0.0.1", "ip_private"],
        ["64:ff9b:1::a9fe:a9fe", "64:ff9b:1::169.254.169.254", "ip_cloud_metadata"],
        ["64:ff9b:1::7f00:1", "64:ff9b:1::127.0.0.1", "ip_loopback"],
      ];
      for (const [hex, dotted, bucket] of pairs) {
        expect(classify(hex)).toEqual([bucket]);
        expect(classify(dotted)).toEqual([bucket]);
      }
    });

    it("S1 names the wrapper in the detail so the IPv4 verdict is explained", () => {
      const [f] = ipClassification.run({ host: "64:ff9b::a9fe:a9fe" } as InspectionContext);
      expect(f?.code).toBe("ip_cloud_metadata");
      expect(f?.detail).toContain("169.254.169.254");
      expect(f?.detail).toContain("NAT64 well-known prefix 64:ff9b::/96");
    });

    it("S1 a wrapper around an ORDINARY public IPv4 stays unclassified", () => {
      for (const h of [
        "::ffff:808:808",
        "64:ff9b::808:808",
        "::808:808",
        "::ffff:8.8.8.8",
        "64:ff9b:1::808:808",
      ]) {
        expect(classify(h)).toEqual([]);
      }
    });

    // LINK-vwehpsdv. Adding `excludeLow: [0, 1]` to the NAT64 rows in
    // LOW32_WRAPPERS was proposed and DECLINED — see the `excludeLow` doc
    // comment in parse/ip.ts. These three were previously unpinned by ANY test,
    // so that edit would have silenced them with nothing failing. That is the
    // whole point of this block: it is the mutation guard for the decline.
    it("LINK-vwehpsdv the BASE of each NAT64 prefix stays ip_reserved", () => {
      for (const h of ["64:ff9b::", "64:ff9b::1", "64:ff9b:1::"]) {
        expect(classify(h)).toEqual(["ip_reserved"]);
      }
    });

    it("LINK-vwehpsdv 64:ff9b::1 is wrapped 0.0.0.1, NOT loopback", () => {
      // The ::/96 carve-out redirects `::1` to ip_loopback because RFC 4291
      // gives it a competing assignment. No such assignment exists inside the
      // NAT64 prefixes, so this must NOT borrow that reading.
      const [f] = ipClassification.run({ host: "64:ff9b::1" } as InspectionContext);
      expect(f?.code).toBe("ip_reserved");
      expect(f?.detail).toContain("0.0.0.1");
      expect(f?.detail).toContain("NAT64 well-known prefix 64:ff9b::/96");
      expect(classify("64:ff9b::1")).not.toContain("ip_loopback");
    });

    it("LINK-vwehpsdv ::  and ::1 keep their OWN identities (the precedent that does not transfer)", () => {
      expect(classify("::")).toEqual(["ip_reserved"]);
      expect(classify("::1")).toEqual(["ip_loopback"]);
    });

    it("LINK-evooubiz names the RFC 8215 prefix in the detail too", () => {
      const [f] = ipClassification.run({ host: "64:ff9b:1::a9fe:a9fe" } as InspectionContext);
      expect(f?.code).toBe("ip_cloud_metadata");
      expect(f?.detail).toContain("169.254.169.254");
      expect(f?.detail).toContain("NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215)");
    });

    it("LINK-evooubiz declined transition prefixes are untouched", () => {
      // 6to4's v4 is the encapsulating ROUTER and Teredo's two candidates are a
      // server and a bit-complemented client — in neither case is the embedded
      // IPv4 the destination, so they get no bucket. This is a decision, not a
      // gap: both are now distinguishable in the range table (S3).
      const declined = [
        "2002:a9fe:a9fe::", // 6to4
        "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
      ];
      for (const h of declined) {
        expect(classify(h)).toEqual([]);
      }
    });

    it("LINK-evooubiz RFC 6052 network-specific prefixes are never speculatively unwrapped", () => {
      // These are ordinary-looking addresses that WOULD decode to a sensitive
      // IPv4 if the network-specific layouts were tried. Speculating costs 14%
      // of random addresses a spurious bucket, so nothing here may classify.
      for (const h of [
        "2001:db8::a9fe:a9fe", // /96 layout — v4 sits in the low 32 bits
        "2001:db8:122:344:a9:fea9:fe00::", // /64 layout, u-byte zero
        "2001:db8:c0a8:1::", // /32 layout carrying 192.168.0.1
      ]) {
        expect(classify(h), h).toEqual([]);
      }
    });

    it("S1 ::1 stays loopback and :: stays reserved (not v4-compatible wrappers)", () => {
      expect(classify("::1")).toEqual(["ip_loopback"]);
      expect(classify("::0.0.0.1")).toEqual(["ip_loopback"]);
      expect(classify("::")).toEqual(["ip_reserved"]);
      expect(classify("::0.0.0.0")).toEqual(["ip_reserved"]);
    });

    it("S1 a dotted quad OUTSIDE a wrapper prefix no longer suppresses the IPv6 bucket", () => {
      // `fe80::1.2.3.4` is link-local carrying an arbitrary interface id, not a
      // wrapped 1.2.3.4 — the v6 bucket must win instead of being swallowed.
      expect(classify("fe80::1.2.3.4")).toEqual(["ip_link_local"]);
    });
  });

  it("detail names the bucket meaning and the canonical address", () => {
    const [f] = ipClassification.run({ host: "169.254.169.254" } as InspectionContext);
    expect(f?.code).toBe("ip_cloud_metadata");
    expect(f?.detail).toContain("169.254.169.254");
    expect(f?.detail).toContain("metadata");
  });

  // S3 — every range bucket carries the registry row that produced it, so the
  // verdict is checkable against the RFC that defines the block.
  describe("S3 detail carries the IANA name + RFC citation", () => {
    it.each([
      { host: "10.0.0.1", name: "Private-Use", rfc: "[RFC1918]" },
      { host: "127.0.0.1", name: "Loopback", rfc: "[RFC1122]" },
      { host: "169.254.10.20", name: "Link Local", rfc: "[RFC3927]" },
      { host: "100.64.0.1", name: "Shared Address Space", rfc: "[RFC6598]" },
      { host: "224.0.0.1", name: "Multicast", rfc: "[RFC5771]" },
      { host: "fc00::1", name: "Unique-Local", rfc: "[RFC4193]" },
      { host: "fe80::1", name: "Link-Local Unicast", rfc: "[RFC4291]" },
      { host: "ff02::1", name: "Multicast", rfc: "[RFC4291]" },
    ])("$host cites $name $rfc", ({ host, name, rfc }) => {
      const [f] = ipClassification.run({ host } as InspectionContext);
      expect(f?.detail).toContain(`IANA ${name}`);
      expect(f?.detail).toContain(rfc);
    });

    it("the vendor-documented metadata table carries NO registry citation", () => {
      const c = classifyHost("169.254.169.254");
      expect(c?.bucket).toBe("ip_cloud_metadata");
      expect(c?.rangeName).toBeUndefined();
      expect(c?.rangeRfc).toBeUndefined();
      expect(detailOf("169.254.169.254")).not.toContain("IANA");
    });
  });
});

function detailOf(host: string): string {
  return ipClassification.run({ host } as InspectionContext)[0]?.detail ?? "";
}

describe("cloud-metadata provider table", () => {
  const detailFor = (host: string): string =>
    ipClassification.run({ host } as InspectionContext)[0]?.detail ?? "";

  it("covers the documented provider set (no silent drift)", () => {
    expect(CLOUD_METADATA_ENDPOINTS.map((e) => e.address)).toEqual([
      "169.254.169.254",
      "fd00:ec2::254",
      "192.0.0.192",
      "100.100.100.200",
      "168.63.129.16",
      "169.254.170.2",
      "169.254.170.23",
      "fd00:ec2::23",
      "169.254.0.23",
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
    { host: "168.63.129.16", provider: "Azure (WireServer host channel)" },
    { host: "169.254.170.2", provider: "AWS (ECS task credentials)" },
    { host: "169.254.170.23", provider: "AWS (EKS Pod Identity)" },
    { host: "fd00:ec2::23", provider: "AWS (EKS Pod Identity, IPv6)" },
    { host: "169.254.0.23", provider: "Tencent Cloud" },
  ])("detail for $host names the provider ($provider)", ({ host, provider }) => {
    const detail = detailFor(host);
    expect(detail).toContain(provider);
    expect(detail).toContain("instance-metadata endpoint");
  });

  // The Azure WireServer row is the only one in the table that no range rule can
  // ever reach: 168.63.129.16 is in genuine PUBLIC space (Microsoft presents it
  // as a "virtual public IP"), so before the row landed it classified as nothing
  // at all — `info` 0.00 with zero reasons, unlike every other endpoint here,
  // which at least picks up a link-local/private/reserved bucket from its
  // enclosing range. Deleting the row therefore fails silently rather than
  // downgrading visibly, which is exactly what this pins.
  it("the Azure WireServer endpoint is public-range — the table is its ONLY source of a bucket", () => {
    const neighbors = ["168.63.129.15", "168.63.129.17", "168.63.130.16"];
    for (const host of neighbors) {
      expect(classifyHost(host), `${host} must stay unclassified`).toBeNull();
    }
    expect(classifyHost("168.63.129.16")?.bucket).toBe("ip_cloud_metadata");
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
