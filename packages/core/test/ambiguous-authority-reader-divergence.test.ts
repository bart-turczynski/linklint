import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanAmbiguousAuthority } from "../src/detectors/ambiguous-authority.js";

/**
 * `ambiguous_authority` — the reader-divergence ledger (LINK-ouljoseh).
 *
 * `docs/architecture.md` §1.1 form 2 is DESTINATION-scoped: "two conforming
 * readers resolve the same string to DIFFERENT DESTINATIONS", and §6 states the
 * discriminator from the other end — "the discriminator is *disagreement
 * between standards*, not exotic input". This file is the evidence layer for
 * that claim, one shape at a time.
 *
 * Every URL below was run through SEVEN real readers on 2026-08-25 and the
 * results are recorded verbatim beside the assertion, so a later reader can
 * check the claim instead of re-deriving it:
 *
 *   - WHATWG   `new URL(u).host`                    (Node 26, whatwg-url)
 *   - legacy   `require("node:url").parse(u).host`  (Node 26)
 *   - Python   `urllib.parse.urlsplit(u)`           (CPython 3)
 *   - Go       `net/url.Parse(u)`                   (go1.x)
 *   - PHP      `parse_url(u)`                       (php 8)
 *   - Java     `new java.net.URI(u).getHost()`      (OpenJDK 21)
 *   - Java     `new java.net.URL(u).getHost()`      (OpenJDK 21)
 *
 * The previous commit pinned the SHIPPED behavior — a blanket "different URL
 * parsers may resolve a different host" attached to all seven sub-signals. Four
 * of those seven could not produce a single pair of readers reaching different
 * hosts. This file now asserts the corrected split, and the guards below are
 * the ones that were RED before the fix.
 */

/** The corrected different-host clause. Backed by a named pair, per shape. */
const DIFFERENT_HOST_CLAIM = "two conforming readers resolve a different host";
/** The corrected accept-vs-reject clause. Explicitly denies different-host. */
const ACCEPT_VS_REJECT_CLAIM = "none reaches a different host";
/** The blanket sentence this fix removed. It must not come back on any shape. */
const RETIRED_CLAIM = "different URL parsers may resolve a different host";

const detail = (input: string): string => scanAmbiguousAuthority(input)[0]?.detail ?? "";
const codes = (input: string): string[] => inspect(input).reasons.map((r) => r.code);

describe("SURVIVES — different host, with a named pair of readers", () => {
  it("backslash: WHATWG reaches good.com, Python urlsplit reaches evil.com", () => {
    // WHATWG "good.com" | legacy "good.com" | Python "evil.com" | PHP "evil.com"
    // | Go REJECT(invalid userinfo) | Java URI/URL REJECT.
    const u = "http://good.com\\@evil.com/";
    expect(codes(u)).toContain("ambiguous_authority");
    expect(detail(u)).toContain("backslash");
    expect(detail(u)).toContain(DIFFERENT_HOST_CLAIM);
    expect(detail(u)).not.toContain(RETIRED_CLAIM);
  });

  it("whitespace_in_authority: node legacy reaches 127.0.0.1, Python reaches the whole run", () => {
    // legacy "127.0.0.1" | Python "127.0.0.1 foo.google.com" | PHP the same as
    // Python | WHATWG/Go/Java REJECT. Two accepting readers, two hosts — Tsai's
    // glibc-NSS shape, where the validator and the resolver split.
    const u = "http://127.0.0.1 foo.google.com/";
    expect(detail(u)).toContain("whitespace_in_authority");
    expect(detail(u)).toContain(DIFFERENT_HOST_CLAIM);
  });

  it("slash_confusion (empty authority): WHATWG reaches evil.com, Go reaches no host", () => {
    // WHATWG "evil.com" | Go Host "" Path "/evil.com" | Python netloc "" |
    // legacy "" | PHP REJECT | Java URI null / URL "".
    const r = inspect("https:///evil.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
    expect(detail("https:///evil.com")).toContain("slash_confusion");
    expect(detail("https:///evil.com")).toContain(DIFFERENT_HOST_CLAIM);
  });
});

describe("SURVIVES REWORDED — accept-vs-reject, and the detail says so", () => {
  it("multiple_userinfo: five readers reach google.com, Java yields none", () => {
    // WHATWG/legacy/Python/Go/PHP "google.com" | Java URI getHost() null |
    // Java URL getHost() "". NO reader reaches evil.com. The WHATWG URL
    // Standard names the LAST '@' as the boundary; RFC 3986 §3.2.1 excludes '@'
    // from userinfo and calls the authority non-conforming. Real standards
    // disagreement, but between "this host" and "no host" — the shape §1.1
    // grades through `ambiguous_numeric_host`, not through different-host.
    const u = "http://foo@evil.com:80@google.com/";
    expect(inspect(u).parsed?.effectiveHost).toBe("google.com");
    expect(detail(u)).toContain("multiple_userinfo");
    expect(detail(u)).toContain(ACCEPT_VS_REJECT_CLAIM);
    expect(detail(u)).not.toContain(RETIRED_CLAIM);
    expect(detail(u)).not.toContain(DIFFERENT_HOST_CLAIM);
  });

  it("multiple_port: no reader reaches a different machine", () => {
    // WHATWG/legacy/Go/Java-URL REJECT | Python hostname "127.0.0.1" (.port
    // raises) | PHP host "127.0.0.1:11211" | Java URI host null. Kept because it
    // is what keeps this string from collapsing to a bare `parse_error`, which
    // §1.1's fourth rule asks it not to do.
    const u = "http://127.0.0.1:11211:80/";
    const r = inspect(u);
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toEqual(["ambiguous_authority"]);
    expect(detail(u)).toContain("multiple_port");
    expect(detail(u)).toContain(ACCEPT_VS_REJECT_CLAIM);
    expect(detail(u)).not.toContain(RETIRED_CLAIM);
  });

  it("a mixed payload states both clauses separately, never merging them", () => {
    // whitespace (different host) + double '@' (accept-vs-reject) in one string.
    const u = "http://foo@127.0.0.1 @google.com:11211/";
    expect(detail(u)).toContain(DIFFERENT_HOST_CLAIM);
    expect(detail(u)).toContain(ACCEPT_VS_REJECT_CLAIM);
    expect(detail(u)).toContain("whitespace_in_authority");
    expect(detail(u)).toContain("multiple_userinfo");
  });
});

describe("DELETED — shapes with no reader disagreement at all (RED before the fix)", () => {
  it("protocol_relative: every reader resolves www.example.com", () => {
    // Python "www.example.com" | Go "www.example.com" | PHP "www.example.com" |
    // Java URI "www.example.com". WHATWG resolves it against its base to the
    // same host: scheme inheritance is RFC 3986 §4.2 BY DESIGN, not
    // disagreement. Highest-volume shape on the web.
    for (const u of [
      "//www.example.com/a.js",
      "//evil.com",
      "//ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
      "//cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
    ]) {
      expect(codes(u), u).not.toContain("ambiguous_authority");
      expect(scanAmbiguousAuthority(u), u).toEqual([]);
    }
  });

  it("a base-less protocol-relative reference falls back to the honest parse_error", () => {
    // §1.1's fourth rule still holds: the string IS unresolvable without a
    // base, and `parse_error` is what says that. What it is not is deceptive.
    const r = inspect("//www.example.com/a.js");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toEqual(["parse_error"]);
  });

  it("slash_confusion path branch: all SEVEN readers resolve target.com", () => {
    // WHATWG/legacy/Python/Go/PHP/Java-URI/Java-URL all report host
    // "target.com" with path "/////evil.com". This was the branch shipping
    // CRITICAL off a disagreement that does not exist.
    const r = inspect("http://target.com/////evil.com");
    expect(r.parsed?.effectiveHost).toBe("target.com");
    expect(r.reasons.map((x) => x.code)).not.toContain("ambiguous_authority");
    // What is left is `suspicious_extension` on the `.com` executable suffix —
    // an unrelated finding that was never the parser claim.
    expect(r.severity).not.toBe("critical");
  });

  it("slash_confusion path branch stays silent on a path with no extension bait", () => {
    const r = inspect("http://target.com/////evil.example/page");
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.reasons.map((x) => x.code)).not.toContain("ambiguous_authority");
  });

  it("fragment_in_authority: all six accepting parsers reach google.com", () => {
    // WHATWG/legacy/Python/Go/PHP/Java-URI/Java-URL all report "google.com".
    // '#' opens the fragment for every one of them; the '@' after it is
    // fragment text. No reader reaches evil.com.
    for (const u of ["http://google.com#@evil.com/", "https://n.pr#@e.gg"]) {
      expect(codes(u), u).not.toContain("ambiguous_authority");
      expect(inspect(u).score, u).toBe(0);
    }
  });
});

describe("KNOWN GAP — the payload fragment_in_authority was introduced for", () => {
  it("is NOT detected, and deleting the branch did not lose it", () => {
    // `ldap://exampleldap.com#.evilhost.com/a` — the Log4j/JNDI shape where the
    // fragment carries the real target. It has NO '@', so it never matched the
    // `#@` branch, before this change or after it. Recorded as an open gap
    // rather than papered over by a branch that fires on something else.
    const r = inspect("ldap://exampleldap.com#.evilhost.com/a");
    expect(r.reasons.map((x) => x.code)).not.toContain("ambiguous_authority");
    expect(r.score).toBe(0);
  });
});

describe("the retired blanket claim is gone from every shape that can still fire", () => {
  it.each([
    "http://good.com\\@evil.com/",
    "http://127.0.0.1 foo.google.com/",
    "https:///evil.com",
    "http://foo@evil.com:80@google.com/",
    "http://127.0.0.1:11211:80/",
    "http:\\\\google.com",
    "foo://///////bar.com/",
    "https:/\\/\\/\\github.com/foo/bar",
  ])("%s does not assert the retired sentence", (u) => {
    const d = detail(u);
    expect(d).not.toBe("");
    expect(d).not.toContain(RETIRED_CLAIM);
  });
});
