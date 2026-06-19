import { describe, expect, it } from "vitest";
import { analyzeIpv4 } from "../src/parse/ip.js";

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
