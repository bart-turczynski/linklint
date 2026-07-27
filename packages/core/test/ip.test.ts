import { describe, expect, it } from "vitest";
import { analyzeIpv4, analyzeIpv6 } from "../src/parse/ip.js";
import { inspect } from "../src/index.js";

describe("analyzeIpv4", () => {
  it("canonical dotted-decimal is an IP but NOT obfuscated", () => {
    expect(analyzeIpv4("127.0.0.1")).toEqual({ obfuscated: false, canonical: "127.0.0.1" });
    expect(analyzeIpv4("192.168.1.1")).toEqual({ obfuscated: false, canonical: "192.168.1.1" });
  });

  it("decimal dotless is obfuscated", () => {
    expect(analyzeIpv4("2130706433")).toEqual({ obfuscated: true, canonical: "127.0.0.1" });
  });

  it("hex forms are obfuscated", () => {
    expect(analyzeIpv4("0x7f.0.0.1")).toEqual({ obfuscated: true, canonical: "127.0.0.1" });
    expect(analyzeIpv4("0x7f000001")).toEqual({ obfuscated: true, canonical: "127.0.0.1" });
  });

  it("octal forms are obfuscated", () => {
    expect(analyzeIpv4("0177.0.0.1")).toEqual({ obfuscated: true, canonical: "127.0.0.1" });
  });

  it("fewer-than-4 parts pack low-order bytes (obfuscated)", () => {
    expect(analyzeIpv4("1.2.3")).toEqual({ obfuscated: true, canonical: "1.2.0.3" });
  });

  it("non-IP hosts return null", () => {
    expect(analyzeIpv4("example.com")).toBeNull();
    expect(analyzeIpv4("discord4")).toBeNull();
    expect(analyzeIpv4("a.b.c.d")).toBeNull();
  });

  it("out-of-range octets return null", () => {
    expect(analyzeIpv4("999.1.1.1")).toBeNull();
    expect(analyzeIpv4("256.0.0.1")).toBeNull();
  });
});

describe("J5 analyzeIpv6", () => {
  it("canonical literals are IPv6 but NOT obfuscated", () => {
    expect(analyzeIpv6("::1")).toEqual({ obfuscated: false, canonical: "::1", embeddedIpv4: null });
    expect(analyzeIpv6("2001:db8::1")).toEqual({
      obfuscated: false,
      canonical: "2001:db8::1",
      embeddedIpv4: null,
    });
    expect(analyzeIpv6("::")).toEqual({ obfuscated: false, canonical: "::", embeddedIpv4: null });
    expect(analyzeIpv6("1:2:3:4:5:6:7:8")?.obfuscated).toBe(false);
  });

  it("leading-zero hextets are obfuscated, canonical strips them", () => {
    expect(analyzeIpv6("2001:0db8::1")).toEqual({
      obfuscated: true,
      canonical: "2001:db8::1",
      embeddedIpv4: null,
    });
  });

  it("non-maximal / unnecessary zero groups are obfuscated", () => {
    expect(analyzeIpv6("0::1")).toEqual({ obfuscated: true, canonical: "::1", embeddedIpv4: null });
    expect(analyzeIpv6("2001:db8:0:0:0:0:0:1")).toEqual({
      obfuscated: true,
      canonical: "2001:db8::1",
      embeddedIpv4: null,
    });
  });

  // LINK-ibwialex — the mixed form is the RFC 5952 §5 RECOMMENDED spelling behind
  // a recognized wrapper, so it is a canonical form and not obfuscation. The
  // embedded IPv4 is still surfaced: that is what carries the SSRF masquerade.
  it("IPv4-mapped mixed form is NOT obfuscated but still surfaces the embedded IPv4", () => {
    expect(analyzeIpv6("::ffff:127.0.0.1")).toEqual({
      obfuscated: false,
      canonical: "::ffff:7f00:1",
      embeddedIpv4: "127.0.0.1",
      embeddedIpv4Via: "IPv4-mapped prefix ::ffff:0:0/96",
    });
  });

  it("the §5 carve-out accepts ONLY the exact mixed form, per wrapper", () => {
    // Accepted: the §5 spelling for each recognized wrapper.
    for (const accepted of [
      "::ffff:127.0.0.1",
      "64:ff9b::127.0.0.1",
      "64:ff9b:1::127.0.0.1",
      "::192.0.2.1",
    ]) {
      expect(analyzeIpv6(accepted)?.obfuscated).toBe(false);
    }
    // Rejected: same bits, but not the §5 spelling (uncompressed zero run), and
    // a dotted tail under a prefix that is not a recognized wrapper at all.
    for (const rejected of ["0:0:0:0:0:ffff:127.0.0.1", "2001:db8::192.0.2.1"]) {
      expect(analyzeIpv6(rejected)?.obfuscated).toBe(true);
    }
  });

  // S1 — the embedded IPv4 is read from the BITS, so the hex spelling of a
  // wrapper form yields exactly what its dotted-quad spelling yields.
  it("S1 recovers the embedded IPv4 for all three low-32 wrapper prefixes", () => {
    const cases: Array<[string, string, string]> = [
      ["::ffff:7f00:1", "127.0.0.1", "IPv4-mapped prefix ::ffff:0:0/96"],
      ["64:ff9b::a9fe:a9fe", "169.254.169.254", "NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)"],
      ["::7f00:1", "127.0.0.1", "IPv4-compatible prefix ::/96 (deprecated by RFC 4291)"],
      [
        "64:ff9b:1::a9fe:a9fe",
        "169.254.169.254",
        "NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215)",
      ],
    ];
    for (const [host, address, via] of cases) {
      expect(analyzeIpv6(host)).toEqual({
        obfuscated: false, // already the RFC 5952 canonical spelling
        canonical: host,
        embeddedIpv4: address,
        embeddedIpv4Via: via,
      });
    }
  });

  it("S1 hex and dotted spellings of the same bits agree on the embedded IPv4", () => {
    for (const [hex, dotted] of [
      ["::ffff:a9fe:a9fe", "::ffff:169.254.169.254"],
      ["64:ff9b::7f00:1", "64:ff9b::127.0.0.1"],
      ["::a00:1", "::10.0.0.1"],
    ]) {
      const a = analyzeIpv6(hex!);
      const b = analyzeIpv6(dotted!);
      expect(a?.canonical).toBe(b?.canonical);
      expect(a?.embeddedIpv4).toBe(b?.embeddedIpv4);
      expect(a?.embeddedIpv4Via).toBe(b?.embeddedIpv4Via);
    }
  });

  it("S1 ::1 and :: are their own addresses, NOT v4-compatible wrappers", () => {
    // Under a naive ::/96 rule these unwrap to 0.0.0.1 / 0.0.0.0 and stop being
    // loopback / unspecified. Low-32 values 0 and 1 are excluded for that reason.
    for (const host of ["::1", "::", "0::1", "::0.0.0.1", "::0.0.0.0"]) {
      expect(analyzeIpv6(host)?.embeddedIpv4).toBeNull();
    }
  });

  it("S1 leaves the declined transition prefixes alone (LINK-evooubiz)", () => {
    // 6to4 embeds a GATEWAY v4 in hextets 1-2 and Teredo bit-complements the
    // client v4 at the tail — neither is the destination, so neither is
    // unwrapped even though both are now distinguishable in the range table.
    const declined = [
      "2002:a9fe:a9fe::", // 6to4
      "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
    ];
    for (const host of declined) {
      expect(analyzeIpv6(host)?.embeddedIpv4).toBeNull();
    }
  });

  // LINK-evooubiz — RFC 8215 is unwrapped at its BASE /96 only. These are the
  // forms that make the narrow match correct rather than merely conservative:
  // each would decode to a DIFFERENT and wrong IPv4 under a blanket low-32 read
  // of the whole reserved /48.
  it("RFC 8215 is matched at its base /96 only, never across the whole /48", () => {
    const notTheBase: Array<[string, string]> = [
      // /64 layout for prefix 64:ff9b:1:0::/64 carrying 169.254.169.254. A
      // blanket low-32 read sees the all-zero suffix as 254.0.0.0 (in 240/4)
      // and would manufacture ip_reserved.
      ["64:ff9b:1:0:a9:fea9:fe00:0", "/64 layout — low 32 bits are the suffix"],
      // /48 layout for the same IPv4: the v4 straddles the reserved u-byte.
      ["64:ff9b:1:a9fe:a9fe::", "/48 layout — v4 straddles the u-byte"],
      // Inside the reserved /48 but not its base /96 — an operator-chosen subnet
      // whose layout we cannot know.
      ["64:ff9b:1:1::a9fe:a9fe", "subnet of the /48, layout unknown"],
      // Outside the reservation entirely.
      ["64:ff9b:2::a9fe:a9fe", "not the RFC 8215 prefix at all"],
    ];
    for (const [host, why] of notTheBase) {
      expect(analyzeIpv6(host)?.embeddedIpv4, why).toBeNull();
    }
  });

  it("uppercase-only is tolerated (not a deception vector — precision)", () => {
    expect(analyzeIpv6("2001:DB8::1")?.obfuscated).toBe(false);
  });

  it("rejects non-IPv6 / zoned / malformed", () => {
    expect(analyzeIpv6("example.com")).toBeNull();
    expect(analyzeIpv6("127.0.0.1")).toBeNull(); // no colon
    expect(analyzeIpv6("fe80::1%eth0")).toBeNull(); // zone id
    expect(analyzeIpv6("gggg::1")).toBeNull(); // bad hextet
    expect(analyzeIpv6("1:2:3:4:5:6:7:8:9")).toBeNull(); // too many groups
    expect(analyzeIpv6("1::2::3")).toBeNull(); // two `::`
    expect(analyzeIpv6("::ffff:256.0.0.1")).toBeNull(); // bad embedded IPv4
  });

  // LINK-gyywyvtn — RFC 4291 §2.2 allows a dotted quad only as the FINAL 32
  // bits. The "final position" test in parseHextets runs per colon-RUN, so
  // before this fix a quad ending the run LEFT of `::` slipped through: it was
  // final for its run but not for the address. Nothing was mis-scored
  // (`1.2.3.4::` canonicalized to the unclassified `102:304::`), but linklint
  // accepted literals a conforming parser rejects — exactly the divergence from
  // a downstream resolver's view that this epic exists to close.
  it("LINK-gyywyvtn rejects a dotted quad left of `::` (never the final 32 bits)", () => {
    for (const host of [
      "1.2.3.4::", // was accepted as 102:304::
      "1.2.3.4::5", // was accepted as 102:304::5
      "1.2.3.4::5.6.7.8", // quads in BOTH runs
      "1:2:3.4.5.6::", // quad final in the left run, after a hextet
    ]) {
      expect(analyzeIpv6(host), host).toBeNull();
    }
  });

  it("LINK-gyywyvtn keeps every legal quad placement working", () => {
    // The fix must not touch the trailing-quad forms the low-32 unwrappers are
    // built on; `::` present is not itself disqualifying, only a dot to its left.
    const legal: Array<[string, string]> = [
      ["::1.2.3.4", "::102:304"],
      ["::ffff:1.2.3.4", "::ffff:102:304"],
      ["64:ff9b::1.2.3.4", "64:ff9b::102:304"],
      ["1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"],
    ];
    for (const [host, canonical] of legal) {
      expect(analyzeIpv6(host)?.canonical, host).toBe(canonical);
    }
  });
});

describe("J5 ip_obfuscation — IPv6 in inspect()", () => {
  it("canonical IPv6 literals parse to ok and do NOT flag", () => {
    for (const u of ["https://[::1]/", "https://[2001:db8::1]:8080/"]) {
      const r = inspect(u);
      expect(r.status).toBe("ok");
      expect(r.reasons.map((x) => x.code)).not.toContain("ip_obfuscation");
    }
  });

  // LINK-ibwialex. RFC 5952 §5 RECOMMENDS the mixed spelling when a well-known
  // prefix makes the embedded IPv4 identifiable from the address field alone, and
  // RFC 6052 §2.4 extends that to the NAT64 prefixes. Both spellings of one
  // address must therefore reach the same verdict — the destination is what is
  // dangerous, not the notation.
  it("both spellings behind a recognized wrapper agree, and neither is obfuscation", () => {
    for (const [dotted, hex] of [
      ["https://[::ffff:127.0.0.1]/", "https://[::ffff:7f00:1]/"],
      ["https://[64:ff9b::127.0.0.1]/", "https://[64:ff9b::7f00:1]/"],
      ["https://[64:ff9b:1::127.0.0.1]/", "https://[64:ff9b:1::7f00:1]/"],
      ["https://[::192.0.2.1]/", "https://[::c000:201]/"],
    ]) {
      const left = inspect(dotted!);
      const right = inspect(hex!);
      expect(left.status).toBe("ok");
      expect(left.reasons.map((x) => x.code)).not.toContain("ip_obfuscation");
      expect(left.score).toBe(right.score);
      expect(left.reasons.map((x) => x.code).sort()).toEqual(
        right.reasons.map((x) => x.code).sort(),
      );
    }
  });

  it("a dotted tail under an UNRECOGNIZED prefix is still obfuscation", () => {
    // §5 recommends mixed notation only behind a well-known prefix; elsewhere it
    // is a MAY resting on external knowledge, so the carve-out must not apply.
    const r = inspect("https://[2001:db8::192.0.2.1]/");
    const reason = r.reasons.find((x) => x.code === "ip_obfuscation");
    expect(reason).toBeDefined();
    expect(reason!.detail).toContain("2001:db8::c000:201");
  });

  it("a wrapper literal that is non-canonical for another reason still flags", () => {
    // The carve-out accepts exactly the §5 mixed form — not an uncompressed one.
    const r = inspect("https://[0:0:0:0:0:ffff:192.0.2.1]/");
    expect(r.reasons.map((x) => x.code)).toContain("ip_obfuscation");
  });

  it("non-canonical literal (leading zeros) flags with canonical form", () => {
    const r = inspect("https://[2001:0db8::1]/");
    const reason = r.reasons.find((x) => x.code === "ip_obfuscation");
    expect(reason?.detail).toContain("2001:db8::1");
  });

  it("an IPv6 host is treated as an IP (no PSL / domain detectors)", () => {
    const r = inspect("https://[::1]/");
    expect(r.parsed?.isIp).toBe(true);
    expect(r.parsed?.registrableDomain).toBeNull();
  });
});
