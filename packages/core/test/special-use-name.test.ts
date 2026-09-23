import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { SPECIAL_USE_NAMES, matchSpecialUseName } from "../src/data/special-use-names.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { CORPUS } from "./corpus/corpus.js";

// LINK-mgnbgicq — CONVERTED, not deleted. The commit before this one pinned the
// RFC 6761 set as entirely SILENT: `https://foo.invalid/` returned 0.00/info
// with an empty reason list, in both shapes and both modes. Those assertions all
// passed, and this commit turns each of them red and then rewrites it, so the
// diff carries the before and the after in one place.
//
// What changed is the REPORTING obligation, not the scope test. Architecture
// §1.1's fourth rule: a 0.00 with no reasons asserts "there is nothing to say
// about this URL", and that is false for a name a standards body has guaranteed
// will never resolve in the global DNS. Nothing here scores — none of these
// names satisfies any of §1.1's three forms — so the score assertions are
// UNCHANGED and are re-asserted below precisely because they must not move.
//
// The two blocks that were pinned as invariants stay invariant:
//   - the example DOMAINS (example.com/.net/.org) still emit NOTHING. They are
//     second-level reservations under a delegated TLD and they resolve.
//   - the cloud-metadata verdict is byte-for-byte what it was, and
//     metadata.google.internal does NOT double-report.

const NAMES = [
  "localhost",
  "test",
  "invalid",
  "example",
  "local",
  "onion",
  "internal",
  "home.arpa",
  "alt",
] as const;

/** Every name in host position and as `foo.<name>` — the two shapes that matter. */
const SHAPES = NAMES.flatMap((name) => [
  [`https://${name}/`, name] as const,
  [`https://foo.${name}/`, name] as const,
]);

const MODES = [
  ["plain", undefined],
  ["agentMode", { agentMode: true }],
] as const;

describe("the RFC 6761 special-use set now explains itself (LINK-mgnbgicq)", () => {
  for (const [modeLabel, options] of MODES) {
    it.each(SHAPES.map(([url, name]) => [url, name] as const))(
      `${modeLabel}: %s reports special_use_name and STILL scores 0.00/info`,
      (url) => {
        const r = inspect(url, options);
        expect(r.status).toBe("ok");
        // UNCHANGED from the pin commit, and that is the whole design: a
        // weight-0 reason annotates without moving anything a consumer filters on.
        expect(r.score).toBe(0);
        expect(r.severity).toBe("info");
        // CONVERTED: this read `toEqual([])` one commit ago.
        expect(r.reasons.map((x) => x.code)).toEqual(["special_use_name"]);
        expect(r.reasons[0]?.weight).toBe(0);
      },
    );
  }

  it("the whole set really is reachable as a public suffix — the pin is not vacuous", () => {
    // If tldts ever stopped treating these as suffixes the block above would
    // still pass while covering nothing, because a non-suffix name is silent too.
    for (const name of NAMES) {
      expect(inspect(`https://foo.${name}/`).parsed?.publicSuffix).toBe(name);
    }
  });

  it("the table covers exactly the nine names, and every one is registered", () => {
    expect(SPECIAL_USE_NAMES.map((r) => r.name).sort()).toEqual([...NAMES].sort());
  });

  it("it is weight 0 and non-scoring in the registry, not merely zero by accident", () => {
    expect(REASON_CODES.special_use_name.scoring).toBe(false);
    expect(REASON_CODES.special_use_name.weight).toBe(0);
  });

  it("the LIVING registry carries its own version stamp", () => {
    // `.alt` 2023, `.internal` 2024 — a snapshot, so a verdict has to name it.
    expect(DATA_VERSIONS.specialUseNames).toBe("2026-08-25-rfc6761");
  });
});

describe("the predicate is the UNIFORM RFC-fixed fact (LINK-mgnbgicq)", () => {
  // Getting this wrong ships a false claim, so the wording is asserted, not
  // trusted. Two shorter phrasings are each false of part of the set.
  const PREDICATE =
    "reserved, never delegated in the global DNS root, never publicly resolvable";

  it.each([...NAMES])("%s states the predicate verbatim", (name) => {
    const detail = inspect(`https://foo.${name}/`).reasons[0]?.detail ?? "";
    expect(detail).toContain(PREDICATE);
  });

  it('never says "cannot resolve" — FALSE for .internal and .local in situ', () => {
    for (const name of NAMES) {
      expect(inspect(`https://foo.${name}/`).reasons[0]?.detail).not.toContain("cannot resolve");
    }
  });

  it('never says "context-dependent" — FALSE for .invalid, which names nothing anywhere', () => {
    for (const name of NAMES) {
      expect(inspect(`https://foo.${name}/`).reasons[0]?.detail).not.toContain("context-dependent");
    }
  });

  it("the category detail sits BENEATH the predicate, and the set is not homogeneous", () => {
    const kinds = new Set(SPECIAL_USE_NAMES.map((r) => r.referent));
    expect(kinds).toEqual(
      new Set(["no-referent", "locally-scoped", "machine-relative", "separate-namespace"]),
    );
    // .localhost is the LEAST context-dependent name in the set: RFC 6761 §6.3
    // MANDATES loopback, so every resolver everywhere gives the same answer.
    expect(matchSpecialUseName("foo.localhost")?.referent).toBe("machine-relative");
    expect(inspect("https://foo.localhost/").reasons[0]?.detail).toContain("MANDATES loopback");
    // .invalid and .alt have no referent anywhere.
    expect(matchSpecialUseName("foo.invalid")?.referent).toBe("no-referent");
    expect(matchSpecialUseName("foo.alt")?.referent).toBe("no-referent");
    // .onion is a separate namespace, not an absence of one.
    expect(matchSpecialUseName("x.onion")?.referent).toBe("separate-namespace");
  });
});

describe("matching is whole-label suffix, longest first (LINK-mgnbgicq)", () => {
  it("does not fire on an ordinary domain that merely ENDS in the letters", () => {
    for (const host of [
      "notinvalid.com",
      "myinternal.com",
      "thelocal.net",
      "alternative.org",
      "protest.com",
      "onionring.co.uk",
    ]) {
      expect(inspect(`https://${host}/`).reasons.map((x) => x.code)).not.toContain(
        "special_use_name",
      );
    }
  });

  it("home.arpa is matched as two labels, and bare `arpa` is NOT reserved here", () => {
    expect(matchSpecialUseName("foo.home.arpa")?.name).toBe("home.arpa");
    // `arpa` is a delegated infrastructure TLD. in-addr.arpa must stay quiet.
    expect(matchSpecialUseName("1.0.168.192.in-addr.arpa")).toBeUndefined();
    expect(
      inspect("https://1.0.168.192.in-addr.arpa/").reasons.map((x) => x.code),
    ).not.toContain("special_use_name");
  });

  it("drops ONE trailing root dot, exactly like the cloud-metadata matcher", () => {
    const r = inspect("https://foo.invalid./");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("special_use_name");
    // And it does not swallow the FQDN finding, which is a different fact.
    expect(codes).toContain("fqdn_root_label");
  });

  it("is case-insensitive", () => {
    expect(inspect("https://FOO.INVALID/").reasons.map((x) => x.code)).toContain(
      "special_use_name",
    );
  });

  it("IP literals are exempt — they are not domain names", () => {
    for (const host of ["127.0.0.1", "[::1]", "192.168.1.1"]) {
      expect(inspect(`https://${host}/`).reasons.map((x) => x.code)).not.toContain(
        "special_use_name",
      );
    }
  });
});

describe("the sharpened inconsistency the fourth rule closes (LINK-mgnbgicq)", () => {
  it("192.168.1.1 says something about a private network; svc.internal now does too", () => {
    const literal = inspect("https://192.168.1.1/");
    // Was 0.20. Since LINK-bwqhvjcs (architecture §6.1.10) the literal reports
    // at weight 0 too, so the two now say their piece the same way.
    expect(literal.score).toBe(0);
    expect(literal.reasons.map((x) => x.code)).toContain("ip_private");

    const name = inspect("https://svc.internal/");
    // Still 0.00 — the name is not a deception finding and never was.
    expect(name.score).toBe(0);
    expect(name.severity).toBe("info");
    // But no longer silent, which is the whole of what changed.
    expect(name.reasons.map((x) => x.code)).toEqual(["special_use_name"]);
  });
});

describe("the RFC 6761 EXAMPLE DOMAINS are EXCLUDED (LINK-mgnbgicq)", () => {
  // RFC 6761 §6.5 reserves `.example` AND `example.com` / `.net` / `.org` in the
  // same section, but the two halves are not the same fact. `.example` is a TLD
  // that was never delegated. `example.com` is a SECOND-LEVEL reservation under
  // `com`, which is delegated and which resolves — IANA operates the site. The
  // measurable difference is the public suffix, pinned here, and it is what a
  // suffix-scoped check keys on.
  it.each(["example.com", "example.net", "example.org"])(
    "%s has a DELEGATED public suffix and does NOT fire",
    (host) => {
      const r = inspect(`https://${host}/`);
      expect(r.parsed?.publicSuffix).toBe(host.split(".")[1]);
      expect(r.parsed?.registrableDomain).toBe(host);
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      // UNCHANGED across both commits. Roughly a quarter of the labeled
      // corpus uses one of these hosts as a neutral stand-in — measured below —
      // so a table that swept them in would annotate that whole population with
      // a claim about the stand-in rather than about the string under test.
      expect(r.reasons.map((x) => x.code)).toEqual([]);
      expect(matchSpecialUseName(host)).toBeUndefined();
    },
  );

  it("the exclusion really is load-bearing — measure the share it protects", () => {
    // The prose in this file, `data/special-use-names.ts`, `docs/architecture.md`
    // §1.1 and `docs/reason-codes.md` all say "roughly a quarter of the labeled
    // corpus". A restated number rots; the SHARE is what the argument needs, so
    // that is what is asserted, with a floor rather than an equality so a peer
    // appending rows cannot turn this red for a reason that is not drift.
    const mentions = CORPUS.filter((r) => /example\.(com|net|org)/.test(r.input));
    expect(mentions.length / CORPUS.length).toBeGreaterThan(0.15);

    // And every row whose ACTUAL HOST is one of them is silent — which is the
    // claim the share supports. The filter is on the parsed host, not on the
    // input string: three corpus rows spell `example.com` inside a
    // separator-lookalike or userinfo trick whose real host is `host.example` or
    // `localhost`, and those SHOULD fire. Filtering on the string would have
    // asserted the opposite of what this code is for.
    let checked = 0;
    for (const row of mentions) {
      const result = inspect(row.input, row.options);
      const reg = result.parsed?.registrableDomain?.toLowerCase();
      if (reg !== "example.com" && reg !== "example.net" && reg !== "example.org") continue;
      checked++;
      expect(result.reasons.map((x) => x.code)).not.toContain("special_use_name");
    }
    expect(checked).toBeGreaterThan(50);
  });

  it("but the .example TLD itself IS covered — the line is the delegation, not the word", () => {
    expect(inspect("https://foo.example/").reasons.map((x) => x.code)).toContain(
      "special_use_name",
    );
    expect(matchSpecialUseName("foo.example")?.name).toBe("example");
  });
});

describe("the cloud-metadata collision, decided: SUPPRESS (LINK-mgnbgicq)", () => {
  const GCP = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

  it("plain mode: metadata.google.internal reports ip_cloud_metadata (weight 0)", () => {
    const r = inspect(GCP);
    // Was 0.75/high; weight 0 since LINK-bwqhvjcs (architecture §6.1.10).
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons.map((x) => x.code)).toEqual(["ip_cloud_metadata"]);
  });

  it("NO DOUBLE-REPORT: the informational code suppresses itself here, in both modes", () => {
    // The decision, pinned. `.internal` is a reserved suffix and this host sits
    // under it, so a naive suffix-driven code would fire on the ONE host in the
    // class that already carries a verdict. Two reasons are owed:
    //   1. the fourth rule's trigger is a 0.00 with no reasons. A host carrying
    //      an ip_cloud_metadata finding is not being silently passed, so
    //      nothing is owed (true at 0.75, and still true at weight 0).
    //   2. the predicate would be FALSE where it landed. "never publicly
    //      resolvable" is beside the point for a host whose entire hazard is
    //      that it resolves, reliably, to a credential-vending endpoint.
    const urls = [GCP, "http://metadata.google.internal/", "http://metadata.google.internal./"];
    for (const options of [undefined, { agentMode: true }]) {
      for (const url of urls) {
        expect(inspect(url, options).reasons.map((x) => x.code)).not.toContain(
          "special_use_name",
        );
      }
    }
  });

  it("the suppression does NOT generalise — it is table membership, not 'some code fired'", () => {
    // A host that scores for an unrelated reason and also sits under a reserved
    // suffix reports BOTH. Only the cloud-metadata table suppresses.
    const r = inspect("http://paypal.com@foo.internal/login");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("userinfo_present");
    expect(codes).toContain("special_use_name");
    expect(r.score).toBeGreaterThan(0);
  });

  it("agentMode: it stacks to 1.00/critical with ssrf_cloud_metadata", () => {
    const r = inspect(GCP, { agentMode: true });
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("ip_cloud_metadata");
    expect(codes).toContain("ssrf_cloud_metadata");
  });

  it.each([
    "http://metadata.google.internal.evil.com/",
    "http://svc.internal/",
    "http://foo.metadata.example.com/",
    "http://metadata.mycorp.com/",
    "http://my-instance-data.example.org/",
  ])("%s is not a metadata endpoint, in either mode", (url) => {
    for (const options of [undefined, { agentMode: true }]) {
      const codes = inspect(url, options).reasons.map((x) => x.code);
      expect(codes).not.toContain("ip_cloud_metadata");
      expect(codes).not.toContain("ssrf_cloud_metadata");
    }
  });

  it("svc.internal — LINK-hvawpgos's own independence example — still scores 0.00 in both modes", () => {
    // The claim that file records is "svc.internal stays at 0.00 under both
    // outcomes", and it is a claim about the SCORE. It holds exactly: mgnbgicq
    // has now been decided IN, and the score did not move by a thousandth,
    // because the code it added carries weight 0. What the host gained is a
    // sentence, which is what the independence argument said it could not lose.
    for (const options of [undefined, { agentMode: true }]) {
      const r = inspect("http://svc.internal/", options);
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).toEqual(["special_use_name"]);
    }
  });
});
