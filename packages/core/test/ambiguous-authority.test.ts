import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanAmbiguousAuthority } from "../src/detectors/ambiguous-authority.js";

/** Sub-signals named in the `ambiguous_authority` detail, for assertions. */
const detail = (input: string): string => {
  const f = scanAmbiguousAuthority(input);
  return f[0]?.detail ?? "";
};
const codes = (input: string) => inspect(input).reasons.map((r) => r.code);

describe("J1 ambiguous_authority — canonical payloads (Tsai BH US-17)", () => {
  it("multiple_userinfo (double @) — parseable, stays ok + scoring reason", () => {
    const r = inspect("http://foo@evil.com:80@google.com/");
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
    expect(detail(r.input)).toContain("multiple_userinfo");
  });

  // `fragment_in_authority` was DELETED (LINK-ouljoseh) — all seven readers
  // resolve `google.com` for `http://google.com#@evil.com/`, so the sub-signal
  // asserted a disagreement that does not exist. The evidence, the named
  // readers, and the Log4j-class payload it never matched are in
  // `ambiguous-authority-reader-divergence.test.ts`.
  it("fragment_in_authority is gone — a '#@' tail is not parser ambiguity", () => {
    expect(codes("http://google.com#@evil.com/")).not.toContain("ambiguous_authority");
  });

  it("whitespace_in_authority (the 'curl won't fix it' bypass)", () => {
    expect(detail("http://foo@127.0.0.1 @google.com:11211/")).toContain(
      "whitespace_in_authority",
    );
  });

  it("multiple_port — unresolvable, becomes invalid WITH a reason (not bare parse_error)", () => {
    const r = inspect("http://127.0.0.1:11211:80/");
    expect(r.status).toBe("invalid");
    expect(r.score).toBeNull();
    expect(r.reasons.map((x) => x.code)).toEqual(["ambiguous_authority"]);
    expect(r.reasons[0]!.detail).toContain("multiple_port");
    expect(r.checksRun).toEqual(["lexical"]);
  });

  it("backslash (browsers fold \\ to /) — scheme separator", () => {
    const r = inspect("http:\\\\google.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
    expect(r.reasons[0]!.detail).toContain("backslash");
  });

  it("backslash in authority — good.com\\@evil.com resolves to evil.com, flagged", () => {
    const r = inspect("http://good.com\\@evil.com");
    expect(r.status).toBe("ok");
    expect(r.parsed?.effectiveHost).toBe("evil.com");
    expect(detail(r.input)).toContain("backslash");
  });

  it("slash_confusion — empty authority http:///", () => {
    const r = inspect("http:///google.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons[0]!.detail).toContain("slash_confusion");
  });

  it("slash_confusion — many slashes http://///evil.com", () => {
    expect(detail("http://///evil.com")).toContain("slash_confusion");
  });

  // The PATH branch of `slash_confusion` was DELETED (LINK-ouljoseh): all seven
  // readers resolve `target.com` for `http://target.com/////evil.com`, and it
  // was the branch shipping CRITICAL. The empty-authority branch above stays —
  // WHATWG dials `evil.com` there while Go and Python dial nothing.
  it("slash_confusion does NOT fire on a network-path reference in the path", () => {
    const r = inspect("http://target.com/////evil.com");
    expect(r.status).toBe("ok");
    expect(r.parsed?.effectiveHost).toBe("target.com");
    expect(codes(r.input)).not.toContain("ambiguous_authority");
  });

  // `protocol_relative` was DELETED (LINK-ouljoseh): scheme inheritance is
  // RFC 3986 §4.2 by design and every reader lands on the same host.
  it("protocol_relative is gone — //evil.com is a bare parse_error again", () => {
    const r = inspect("//evil.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).not.toContain("ambiguous_authority");
  });

  it("multi-candidate host injection (multiple @ + whitespace)", () => {
    expect(codes("http://1.1.1.1 &@2.2.2.2# @3.3.3.3/")).toContain("ambiguous_authority");
  });
});

describe("J1 — reaches >= high on its own (SC-1) and emits one reason code", () => {
  it("scores high from a single parseable payload", () => {
    // Re-pointed by LINK-ouljoseh at a payload that HAS a named reader pair.
    // The old exemplar (`http://target.com/////evil.com`) was the false path
    // branch — all seven readers resolve `target.com` there. This one forks for
    // real: WHATWG `new URL` reaches `good.com`, Python `urlsplit` reaches
    // `evil.com`.
    const r = inspect("http://good.com\\@evil.com/");
    expect(["high", "critical"]).toContain(r.severity);
    expect(r.score).toBeGreaterThan(0.5);
    expect(r.reasons.map((x) => x.code)).toContain("ambiguous_authority");
  });

  it("multiple sub-signals collapse to a single ambiguous_authority reason", () => {
    const r = inspect("http://foo@127.0.0.1 @google.com:11211/");
    const hits = r.reasons.filter((x) => x.code === "ambiguous_authority");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.detail).toContain("multiple_userinfo");
    expect(hits[0]!.detail).toContain("whitespace_in_authority");
  });
});

describe("J1 — must not over-flag legitimate authorities (SC-2)", () => {
  const benign = [
    "https://www.example.com/path",
    "https://user:pass@host.example.com/login", // single, legitimate userinfo
    "https://[::1]:8080/", // IPv6 literal with port — many colons, all bracketed
    "https://example.com:8443/a/b?x=1#frag",
    "https://example.com//foo//bar", // accidental double slashes in path
    "example.com/abc", // bare scheme-less — out of scope
    "google.com:8080/x", // host:port without scheme
    "ftp://files.example.com/pub",
  ];
  for (const input of benign) {
    it(`no ambiguous_authority for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("ambiguous_authority");
    });
  }
});

describe("J1 — scanAmbiguousAuthority is total and gate-correct", () => {
  it("returns [] for empty / non-URL input", () => {
    for (const i of ["", "   ", "💥", "://", "@@@", "hello world", "ht!tp://x"]) {
      expect(scanAmbiguousAuthority(i.trim())).toEqual([]);
    }
  });

  it("does not turn a plain empty-authority http:// into a finding", () => {
    expect(scanAmbiguousAuthority("http://")).toEqual([]);
    expect(inspect("http://").reasons.map((x) => x.code)).toEqual(["parse_error"]);
  });

  it("ignores opaque schemes (no authority)", () => {
    expect(scanAmbiguousAuthority("javascript:alert(1)")).toEqual([]);
    expect(scanAmbiguousAuthority("mailto:a@b.com")).toEqual([]);
  });
});
