import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { parse } from "../src/parse/parse.js";
import { analyzeIpv6 } from "../src/parse/ip.js";
import { classifyHost } from "../src/detectors/ip-classification.js";
import { compareUrls } from "../src/compare/compare-urls.js";

/**
 * RFC 6874 IPv6 ZONE IDENTIFIERS, measured and pinned (LINK-zjczfkgr).
 *
 * WHY THIS FILE EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO. OpenStack's Nova
 * metadata-service admin guide has documented since Victoria that guests reach
 * the metadata service "at 169.254.169.254 or at fe80::a9fe:a9fe". That is the
 * same shape as the GCP IPv6 gap closed by LINK-eyjfhbzu (`fd20:ce::254`, see
 * `gcp-ipv6-metadata.test.ts`): a documented credential endpoint losing to a
 * broader range. The measurement below confirms it is still open —
 * `[fe80::a9fe:a9fe]` reports `ip_link_local` while its IPv4 sibling reports
 * `ip_cloud_metadata` and escalates to 1.00 under `agentMode`. (Both default
 * verdicts are 0.00 since LINK-bwqhvjcs, architecture §6.1.10, which put every
 * destination-membership code at weight 0; the agent-mode asymmetry is what
 * remains.)
 *
 * **No row is added here, and no weight moves.** Two things block that decision
 * and only one of them is answerable by measurement:
 *
 * 1. A `fe80::/10` address is ambiguous without a ZONE IDENTIFIER — RFC 4007 §6,
 *    not anything OpenStack says; the Nova page prints the bare address and
 *    mentions no zone at all — so `fe80::a9fe:a9fe%eth0` is the spelling a host
 *    with more than one interface actually needs, and nothing in the tree
 *    recorded what linklint does with one. That is this file: every
 *    zone-identifier spelling is measured against `analyzeIpv6`, `parse`,
 *    `inspect`, `classifyHost` and `compareUrls`, and against WHATWG-URL for
 *    parity. The answers are pinned whether or not a table row is ever added.
 * 2. `fe80::a9fe:a9fe` is a PROXY ANYCAST address, not one vendor's endpoint:
 *    every OpenStack deployment answers on it, and on a network without
 *    OpenStack it is an ordinary link-local address. That is materially weaker
 *    than the GCP/AWS/Azure case and it is a maintainer decision, not a test's.
 *    Nothing below decides it.
 *
 * WHAT THE MEASUREMENT FOUND: linklint rejects every zone-identifier spelling,
 * at the host level, and agrees with WHATWG-URL on all of them. The zone id is
 * never stripped and never mangled — a zoned literal does not reach any IP
 * bucket by a side door, so an OpenStack row (if one were ever added) would be
 * reachable only through the bare `fe80::a9fe:a9fe` spelling.
 *
 * ONE MEASURED PROPERTY OF THE IMPLEMENTATION, recorded so a future reader does
 * not mistake it for coverage: `analyzeIpv6`'s `host.includes("%")` early return
 * is DEFENCE IN DEPTH, not the load-bearing rejection. Deleting that clause and
 * re-running every case below leaves all of them green, because `parseHextets`
 * matches each part against `^[0-9a-fA-F]{1,4}$` and a `%` cannot survive it.
 * What these pins actually bite on is the decision to reject rather than strip:
 * replacing the clause with `host = host.slice(0, host.indexOf("%"))` turns
 * `http://[fe80::a9fe:a9fe%25eth0]/` from `invalid`/`null` into `ok`/0.48
 * (`encoding_obfuscation` + `ip_link_local`) and every describe below goes red.
 */

/** The bare OpenStack IPv6 metadata address, no zone id. */
const BARE = "fe80::a9fe:a9fe";
const BARE_URL = `http://[${BARE}]/`;
/** Its IPv4 sibling, which the endpoint table already carries. */
const V4_URL = "http://169.254.169.254/";

/**
 * Every zone-identifier spelling worth separating, as the HOST TEXT inside the
 * brackets. RFC 6874 percent-encodes the delimiter (`%25`); the raw `%` form is
 * what people actually type; the rest vary the zone body — empty, numeric,
 * uppercase, doubled, re-encoded, containing a nested escape, and containing
 * every character RFC 6874 §2 permits unescaped.
 */
const ZONED_HOSTS: ReadonlyArray<readonly [label: string, host: string]> = [
  ["RFC 6874 percent-encoded delimiter", `${BARE}%25eth0`],
  ["raw delimiter, as typed", `${BARE}%eth0`],
  ["empty zone id", `${BARE}%25`],
  ["empty zone id, raw delimiter", `${BARE}%`],
  ["numeric zone id (Windows interface index)", `${BARE}%251`],
  ["numeric zone id, raw delimiter", `${BARE}%1`],
  ["zero zone id", `${BARE}%250`],
  ["hex-shaped zone id, could pass for a hextet", `${BARE}%25ffff`],
  ["uppercase zone id", `${BARE}%25ETH0`],
  ["doubled zone id", `${BARE}%25eth0%25eth1`],
  ["double-encoded delimiter", `${BARE}%2525eth0`],
  ["escape inside the zone body", `${BARE}%25e%74h0`],
  ["full RFC 6874 unreserved zone body", `${BARE}%25eth-0.1_2~3`],
  ["zone id on a compressed address", "fe80::%25eth0"],
  ["zone id with no address at all", "%25eth0"],
];

const urlOf = (host: string): string => `http://[${host}]/`;
const codesOf = (url: string, agentMode = false): string[] =>
  inspect(url, agentMode ? { agentMode: true } : undefined).reasons.map((r) => r.code);

describe("the gap this evidence is about, re-confirmed and NOT closed (LINK-zjczfkgr)", () => {
  // Committed asserting the UNDER-SCORING. If a later slice adds an OpenStack
  // row to CLOUD_METADATA_ENDPOINTS this test is the one that must be flipped,
  // deliberately, in that slice — the way `gcp-ipv6-metadata.test.ts` was.
  it("the bare fe80::a9fe:a9fe reports the generic link-local bucket (weight 0)", () => {
    const r = inspect(BARE_URL);
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons.map((x) => x.code)).toEqual(["ip_link_local"]);
    expect(classifyHost(BARE)?.bucket).toBe("ip_link_local");
    expect(classifyHost(BARE)?.rangeName).toBe("Link-Local Unicast");
  });

  it("its IPv4 sibling escalates to 1.00 under agentMode — the asymmetry", () => {
    expect(codesOf(V4_URL)).toEqual(["ip_cloud_metadata"]);
    expect(inspect(V4_URL).score).toBe(0);
    expect(codesOf(V4_URL, true).sort()).toEqual(["ip_cloud_metadata", "ssrf_cloud_metadata"]);
    expect(inspect(V4_URL, { agentMode: true }).score).toBeCloseTo(1, 5);
  });

  // `ssrf_cloud_metadata` asks `classifyHost` for the `ip_cloud_metadata`
  // bucket, so the v6 side gets no agent-mode block at all.
  it("agentMode adds nothing on the v6 side — no SSRF block", () => {
    const r = inspect(BARE_URL, { agentMode: true });
    expect(r.reasons.map((x) => x.code)).toEqual(["ip_link_local"]);
    expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
    expect(r.score).toBe(0);
  });
});

describe("a zone identifier makes the host unparseable, at every layer (LINK-zjczfkgr)", () => {
  it.each(ZONED_HOSTS)("%s — analyzeIpv6 rejects `%s`", (_label, host) => {
    expect(analyzeIpv6(host)).toBeNull();
  });

  // The zone id is not stripped on the way past: no zoned spelling reaches ANY
  // IP bucket, so it cannot inherit the bare address's classification.
  it.each(ZONED_HOSTS)("%s — classifyHost returns null for `%s`", (_label, host) => {
    expect(classifyHost(host)).toBeNull();
  });

  it.each(ZONED_HOSTS)("%s — parse() returns null for `%s`", (_label, host) => {
    expect(parse(urlOf(host))).toBeNull();
  });

  it.each(ZONED_HOSTS)("%s — inspect() is invalid with a null score for `%s`", (_label, host) => {
    const r = inspect(urlOf(host));
    expect(r.status).toBe("invalid");
    expect(r.score).toBeNull();
    expect(r.severity).toBeNull();
  });
});

describe("what the caller is told instead of a verdict (LINK-zjczfkgr)", () => {
  const ZONED_URL = urlOf(`${BARE}%25eth0`);

  // §1.1's fourth rule: the failure is NAMED rather than standing in for the
  // whole verdict. This is the `parse_error` FALLBACK shape — the host fails
  // before any detector runs, so `checksRun` is empty rather than `["lexical"]`.
  it("a weight-0 parse_error names the authority region that failed", () => {
    const r = inspect(ZONED_URL);
    expect(r.reasons).toHaveLength(1);
    expect(r.reasons[0]?.code).toBe("parse_error");
    expect(r.reasons[0]?.weight).toBe(0);
    expect(r.reasons[0]?.detail).toContain(`[${BARE}%25eth0]`);
    expect(r.reasons[0]?.detail).toContain("is not a host");
    expect(r.checksRun).toEqual([]);
    expect(r.checksSkipped).toEqual(["lexical", "resolution", "reputation"]);
  });

  // The zone text never reaches the reader as a host, in any field. A stripping
  // implementation would surface the bare address here.
  it("no field carries the zoned host, and none carries the bare address either", () => {
    const serialized = JSON.stringify(inspect(ZONED_URL));
    expect(serialized).not.toContain(`"host":"${BARE}`);
    expect(inspect(ZONED_URL).reasons.map((x) => x.code)).not.toContain("ip_link_local");
  });

  it("rejection does not depend on the scheme, the port, or userinfo", () => {
    for (const url of [
      `https://[${BARE}%25eth0]/`,
      `ftp://[${BARE}%25eth0]/`,
      `http://[${BARE}%25eth0]:8080/x?y=1#z`,
      `http://user@[${BARE}%25eth0]/`,
      `http://[${BARE}%25eth0]`,
    ]) {
      const r = inspect(url);
      expect(r.status, url).toBe("invalid");
      expect(r.score, url).toBeNull();
    }
  });

  // Whitespace inside the authority is a DIFFERENT finding and outranks the
  // parse failure — pinned so the family above is not read as "anything with a
  // `%` in brackets reports `parse_error`".
  it("a space in the zone id is ambiguous_authority, not parse_error", () => {
    const r = inspect(`http://[${BARE}%25 1]/`);
    expect(r.status).toBe("invalid");
    expect(r.score).toBeNull();
    expect(r.reasons.map((x) => x.code)).toEqual(["ambiguous_authority"]);
  });
});

describe("linklint and WHATWG-URL agree on every zone spelling (LINK-zjczfkgr)", () => {
  // Browsers reject zone identifiers in URLs — the WHATWG host parser has no
  // production for them. This pins AGREEMENT rather than an opinion about what
  // ought to happen: linklint refuses exactly where `new URL` throws, so no
  // reader divergence (§1.1 form 2) is created by the refusal.
  const whatwgAccepts = (url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  it.each(ZONED_HOSTS)("%s — both reject `%s`", (_label, host) => {
    expect(whatwgAccepts(urlOf(host))).toBe(false);
    expect(parse(urlOf(host))).toBeNull();
  });

  it("both accept the same literal without a zone id (the control)", () => {
    expect(whatwgAccepts(BARE_URL)).toBe(true);
    expect(parse(BARE_URL)?.host).toBe(BARE);
    expect(new URL(BARE_URL).hostname).toBe(`[${BARE}]`);
  });
});

describe("what an unparseable zone id costs downstream (LINK-zjczfkgr)", () => {
  // NOT a defect claim — a measured consequence, recorded because it is the
  // only place a zone id changes a score rather than removing one. The wrapper
  // is a perfectly parseable URL; only its redirect TARGET is unparseable, so
  // `open_redirect_param` cannot say where the link points and does not fire.
  // What is left is the `%25` escape, at a lower weight.
  it("a zoned target inside a redirect param loses open_redirect_param", () => {
    const bare = inspect(`https://example.com/?next=${BARE_URL}`);
    expect(bare.reasons.map((x) => x.code)).toEqual(["open_redirect_param"]);
    expect(bare.score).toBeCloseTo(0.4, 5);

    const zoned = inspect(`https://example.com/?next=http://[${BARE}%25eth0]/`);
    expect(zoned.status).toBe("ok");
    expect(zoned.reasons.map((x) => x.code)).toEqual(["encoding_obfuscation"]);
    expect(zoned.score).toBeCloseTo(0.35, 5);
  });

  // `compareUrls` reports `undetermined` rather than guessing an origin — the
  // zoned side has no host at all, so same-origin cannot be decided either way.
  it("compareUrls reports undetermined against a zoned URL", () => {
    const c = compareUrls(BARE_URL, `http://[${BARE}%25eth0]/`);
    expect(c.sameOrigin).toBe("undetermined");
    expect(c.sameSite).toBe("undetermined");
    expect(c.left.host).toBe(BARE);
    expect(c.right.host).toBeNull();
    expect(c.right.originKind).toBe("undetermined");
  });
});
