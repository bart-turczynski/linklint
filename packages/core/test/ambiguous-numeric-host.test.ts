import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { ambiguousNumericHost } from "../src/detectors/ambiguous-numeric-host.js";

/**
 * P3 (LINK-slcjsjcs) — ambiguous_numeric_host: malformed-IPv4-shaped hosts that
 * WHATWG rejects (browser parses the whole host as IPv4 and fails) but RFC 3986
 * clients resolve as a literal hostname. Pure lexical, no second parser.
 */

function reasons(input: string): string[] {
  return inspect(input).reasons.map((r) => r.code);
}

function detailFor(input: string): string | undefined {
  return inspect(input).reasons.find((r) => r.code === "ambiguous_numeric_host")?.detail;
}

describe("ambiguous_numeric_host — fires on malformed-IPv4-shaped hosts", () => {
  const pureIpAttempt = [
    "http://256.0.0.1/",
    "http://256.256.256.1/",
    "http://0x100.2.3.4/",
    "http://1.2.3.4.5/",
    "http://01.2.3.4.5/",
    "http://0x100000000/",
    "http://6442450945/",
    "http://0999999999999999999/",
  ];

  it.each(pureIpAttempt)("fires (pure-IP-attempt) on %s", (input) => {
    expect(reasons(input)).toContain("ambiguous_numeric_host");
    // No decodable IP → must NOT be treated as an obfuscated IP.
    expect(reasons(input)).not.toContain("ip_obfuscation");
    expect(detailFor(input)).toContain("malformed IPv4 literal");
  });

  const nameWithNumericTail = [
    "http://foo.1.2.3.4/",
    "http://foo.09/",
    "http://foo.0x4/",
    "http://foo.0x/",
    "http://a.b.256/",
  ];

  it.each(nameWithNumericTail)("fires (name-with-numeric-tail) on %s", (input) => {
    expect(reasons(input)).toContain("ambiguous_numeric_host");
    expect(reasons(input)).not.toContain("ip_obfuscation");
    expect(detailFor(input)).toContain("ends in a numeric/hex label");
  });

  it("scores in the medium band (both sub-shapes at weight 0.3)", () => {
    for (const input of ["http://256.0.0.1/", "http://foo.09/"]) {
      const r = inspect(input);
      expect(r.severity).toBe("medium");
    }
  });
});

describe("ambiguous_numeric_host — trailing root dot is normalized", () => {
  it("treats foo.09. like foo.09 (fires)", () => {
    expect(reasons("http://foo.09./")).toContain("ambiguous_numeric_host");
  });

  it("treats 1.2.3.08. like 1.2.3.08 → ip_obfuscation, NOT ambiguous (real obfuscated IP)", () => {
    // The consistency fix: the recognizer normalizes the root dot, so the dotted
    // and trailing-dot forms agree.
    const plain = reasons("http://1.2.3.08/");
    const dotted = reasons("http://1.2.3.08./");
    expect(plain).toContain("ip_obfuscation");
    expect(dotted).toContain("ip_obfuscation");
    expect(dotted).not.toContain("ambiguous_numeric_host");
  });
});

describe("ambiguous_numeric_host — precision guards (must NOT fire)", () => {
  const benign = [
    "https://3.pool.ntp.org/", // numeric leading label, non-numeric tail
    "http://8.8.8.8/", // valid canonical public IP
    "http://192.168.1.1/", // valid canonical private IP (ip_private, not ambiguous)
    "http://127.0.0.1/", // valid canonical loopback
    "http://2130706433/", // valid dotless IP (obfuscated, decodable) → ip_obfuscation
    "https://example.com/", // ordinary name
    "https://v2.api.example.com/", // numeric-ish but non-numeric labels
    "http://999/", // single dotless number IS a valid inet_aton IP (0.0.3.231)
    // LINK-ibwialex — a valid IPv6 literal never enters WHATWG's IPv4 path, so
    // premise (a) cannot hold however its text ends. These used to fire purely
    // because splitting on "." left a numeric final label.
    "https://[64:ff9b::192.0.2.1]/", // NAT64 well-known prefix, mixed notation
    "https://[::ffff:127.0.0.1]/", // IPv4-mapped, mixed notation
    "https://[2001:db8::192.0.2.1]/", // dotted tail under an unrecognized prefix
  ];

  it.each(benign)("does not fire on %s", (input) => {
    expect(reasons(input)).not.toContain("ambiguous_numeric_host");
  });

  it("obfuscated-but-decodable IPs stay ip_obfuscation, not ambiguous", () => {
    expect(reasons("http://0x7f.0.0.1/")).toContain("ip_obfuscation");
    expect(reasons("http://0x7f.0.0.1/")).not.toContain("ambiguous_numeric_host");
  });

  it("the detector run() is a no-op on an empty host", () => {
    const ctx = { host: "" } as Parameters<typeof ambiguousNumericHost.run>[0];
    expect(ambiguousNumericHost.run(ctx)).toEqual([]);
  });
});
