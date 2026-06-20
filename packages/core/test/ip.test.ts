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

  it("IPv4-mapped form is obfuscated and surfaces the embedded IPv4 (SSRF masquerade)", () => {
    expect(analyzeIpv6("::ffff:127.0.0.1")).toEqual({
      obfuscated: true,
      canonical: "::ffff:7f00:1",
      embeddedIpv4: "127.0.0.1",
    });
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
});

describe("J5 ip_obfuscation — IPv6 in inspect()", () => {
  it("canonical IPv6 literals parse to ok and do NOT flag", () => {
    for (const u of ["https://[::1]/", "https://[2001:db8::1]:8080/"]) {
      const r = inspect(u);
      expect(r.status).toBe("ok");
      expect(r.reasons.map((x) => x.code)).not.toContain("ip_obfuscation");
    }
  });

  it("IPv4-mapped literal flags ip_obfuscation and names the embedded IPv4", () => {
    const r = inspect("https://[::ffff:127.0.0.1]/");
    expect(r.status).toBe("ok");
    const reason = r.reasons.find((x) => x.code === "ip_obfuscation");
    expect(reason).toBeDefined();
    expect(reason!.detail).toContain("127.0.0.1");
    expect(["medium", "high", "critical"]).toContain(r.severity);
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
