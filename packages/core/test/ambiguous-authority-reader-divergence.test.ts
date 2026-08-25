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
 * THIS COMMIT PINS THE SHIPPED BEHAVIOR AS IT IS — including the four shapes
 * where the shipped detail string is FALSE. Nothing here is an endorsement; the
 * `FALSE` comments say exactly which assertions the fix is expected to break,
 * so the follow-up diff shows precisely what stops being asserted.
 */

/** The blanket claim the shipped detector attaches to every sub-signal. */
const SHIPPED_CLAIM = "different URL parsers may resolve a different host";

const detail = (input: string): string => scanAmbiguousAuthority(input)[0]?.detail ?? "";
const codes = (input: string): string[] => inspect(input).reasons.map((r) => r.code);

describe("PIN — shapes whose different-host claim IS backed by two named readers", () => {
  it("backslash: WHATWG reaches good.com, Python urlsplit reaches evil.com", () => {
    // WHATWG "good.com" | legacy "good.com" | Python "evil.com" | PHP "evil.com"
    // | Go REJECT(invalid userinfo) | Java URI/URL REJECT.
    const u = "http://good.com\\@evil.com/";
    expect(codes(u)).toContain("ambiguous_authority");
    expect(detail(u)).toContain("backslash");
    expect(detail(u)).toContain(SHIPPED_CLAIM);
  });

  it("whitespace_in_authority: node legacy reaches 127.0.0.1, Python reaches the whole run", () => {
    // legacy "127.0.0.1" | Python "127.0.0.1 foo.google.com" | PHP the same as
    // Python | WHATWG/Go/Java REJECT. Two accepting readers, two hosts.
    const u = "http://127.0.0.1 foo.google.com/";
    expect(detail(u)).toContain("whitespace_in_authority");
    expect(detail(u)).toContain(SHIPPED_CLAIM);
  });

  it("slash_confusion (empty authority): WHATWG reaches evil.com, Go reaches no host", () => {
    // WHATWG "evil.com" | Go Host "" Path "/evil.com" | Python netloc "" |
    // legacy "" | PHP REJECT | Java URI null / URL "".
    const r = inspect("https:///evil.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
    expect(detail("https:///evil.com")).toContain("slash_confusion");
  });
});

describe("PIN — shapes where the shipped different-host claim is FALSE", () => {
  it("FALSE protocol_relative: every reader resolves www.example.com", () => {
    // Python "www.example.com" | Go "www.example.com" | PHP "www.example.com" |
    // Java URI "www.example.com". WHATWG resolves it against its base to the
    // same host — scheme inheritance is RFC 3986 §4.2 BY DESIGN, not
    // disagreement. Highest-volume shape on the web.
    const u = "//www.example.com/a.js";
    expect(codes(u)).toContain("ambiguous_authority"); // <- expected to break
    expect(detail(u)).toContain("protocol_relative"); // <- expected to break
    expect(detail(u)).toContain(SHIPPED_CLAIM); // <- expected to break
  });

  it("FALSE slash_confusion path branch: all SEVEN readers resolve target.com", () => {
    // WHATWG/legacy/Python/Go/PHP/Java-URI/Java-URL all report host
    // "target.com" with path "/////evil.com". Zero disagreement, and this is
    // the branch shipping CRITICAL.
    const r = inspect("http://target.com/////evil.com");
    expect(r.parsed?.effectiveHost).toBe("target.com");
    expect(r.severity).toBe("critical"); // <- expected to break
    expect(r.score).toBeCloseTo(0.825, 5); // <- expected to break
    expect(detail(r.input)).toContain("slash_confusion"); // <- expected to break
  });

  it("FALSE fragment_in_authority: all six accepting parsers reach google.com", () => {
    // WHATWG/legacy/Python/Go/PHP/Java-URI/Java-URL all report "google.com".
    // The `#` opens the fragment for every one of them; the `@` after it is
    // fragment text. No reader reaches evil.com.
    const u = "http://google.com#@evil.com/";
    expect(codes(u)).toContain("ambiguous_authority"); // <- expected to break
    expect(detail(u)).toContain("fragment_in_authority"); // <- expected to break
    expect(inspect(u).severity).toBe("high"); // <- expected to break
  });

  it("OVER-CLAIM multiple_userinfo: five readers reach google.com, Java yields none", () => {
    // WHATWG/legacy/Python/Go/PHP "google.com" | Java URI getHost() null |
    // Java URL getHost() "". No reader reaches evil.com, so this is
    // accept-vs-reject divergence, NOT different-host.
    const u = "http://foo@evil.com:80@google.com/";
    expect(inspect(u).parsed?.effectiveHost).toBe("google.com");
    expect(detail(u)).toContain("multiple_userinfo");
    expect(detail(u)).toContain(SHIPPED_CLAIM); // <- expected to break
  });

  it("OVER-CLAIM multiple_port: no reader reaches a different machine", () => {
    // WHATWG/legacy/Go/Java-URL REJECT | Python hostname "127.0.0.1" (.port
    // raises) | PHP host "127.0.0.1:11211" | Java URI host null. Every reader
    // that yields anything yields 127.0.0.1; none reaches port 80 elsewhere.
    const u = "http://127.0.0.1:11211:80/";
    expect(inspect(u).status).toBe("invalid");
    expect(detail(u)).toContain("multiple_port");
    expect(detail(u)).toContain(SHIPPED_CLAIM); // <- expected to break
  });
});

describe("PIN — the Log4j-class payload fragment_in_authority was introduced for", () => {
  it("is NOT detected: the motivating case has no '@' and never reached the branch", () => {
    // `ldap://exampleldap.com#.evilhost.com/a` — the JNDI shape where the
    // fragment carries the real target. Every reader reports host
    // "exampleldap.com" (Java URL rejects the scheme). The shipped
    // `fragment_in_authority` branch keys on a leading `@` in the fragment, so
    // it never saw its own motivating payload. Pinned as a KNOWN GAP.
    const r = inspect("ldap://exampleldap.com#.evilhost.com/a");
    expect(r.reasons.map((x) => x.code)).not.toContain("ambiguous_authority");
    expect(r.score).toBe(0);
  });
});
