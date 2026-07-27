import { describe, expect, it } from "vitest";
import { inspect, WEIGHTS } from "../src/index.js";

/**
 * T2.7 revisited (`LINK-ygglwkuy`) — over-long hostnames.
 *
 * This file exists mainly to pin the *distinction*, because it is the one that
 * was got wrong once already: an over-long hostname is reported but NOT scored.
 * Architecture §1.1 excludes "well-formed but unusable" from claim (a) and cites
 * host length as the worked case; a scoring implementation was written and
 * reverted on exactly that reasoning. §1.1's fourth rule adds the other half —
 * report what you can determine, never silently pass — so the fact is announced
 * at weight 0.
 *
 * If a future change makes any assertion here fail by moving the score, that is
 * the reverted design coming back, not an improvement.
 */

const result = (url: string) => inspect(url, { agentMode: true });
const reasons = (url: string) => result(url).reasons.map((r) => r.code);

const longLabel = `https://${"a".repeat(64)}.com`;
// 263 octets of hostname built from legal 9-octet labels: 26 * 9 + 25 dots + ".com".
const longHost = `https://${Array.from({ length: 26 }, () => "abcdefghi").join(".")}.com`;

describe("host_length_unresolvable — announces the fact", () => {
  it("fires on a label over 63 octets", () => {
    expect(reasons(longLabel)).toContain("host_length_unresolvable");
  });

  it("fires on a whole hostname over 253 octets", () => {
    expect(reasons(longHost)).toContain("host_length_unresolvable");
  });

  it("names the limit that was exceeded, not just that something is wrong", () => {
    const detail = result(longLabel).reasons.find(
      (r) => r.code === "host_length_unresolvable",
    )?.detail;
    expect(detail).toMatch(/64 octets/);
    expect(detail).toMatch(/63/);
  });
});

describe("host_length_unresolvable — reported, deliberately NOT scored", () => {
  it("is registered at weight 0", () => {
    expect(WEIGHTS.host_length_unresolvable).toBe(0);
  });

  it("leaves the score and severity exactly where they were", () => {
    // The §1.1 exclusion: every parser reads this host identically and nothing
    // is disguised, so it is not deception. LINK-ygglwkuy was reverted for
    // scoring it. This assertion is that revert, pinned.
    const r = result(longLabel);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("but does NOT return an empty reason list — that is the half that changed", () => {
    // Returning 0.00 with zero reasons asserts "nothing to say about this URL",
    // which is false: it will never resolve.
    expect(result(longLabel).reasons.length).toBeGreaterThan(0);
  });
});

describe("host_length_unresolvable — boundary", () => {
  it.each([
    ["https://example.com/", "ordinary host"],
    [`https://${"a".repeat(63)}.com`, "label at exactly the 63-octet limit"],
    ["https://192.168.1.1/", "IPv4 literal is not a domain name"],
    ["https://[::1]/", "IPv6 literal is not a domain name"],
    ["https://münchen.de/", "IDN well within the limits"],
  ])("stays quiet on %s (%s)", (url) => {
    expect(reasons(url)).not.toContain("host_length_unresolvable");
  });

  it("does not count a trailing root dot toward the 253-octet limit", () => {
    // A hostname of exactly 253 octets plus the legal root dot still resolves.
    // 25 * 9 + 24 dots = 249, plus ".abc" = exactly 253.
    const host = `${Array.from({ length: 25 }, () => "abcdefghi").join(".")}.abc`;
    expect(host.length).toBe(253);
    expect(reasons(`https://${host}./`)).not.toContain("host_length_unresolvable");
  });
});
