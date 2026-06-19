import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanSeparatorLookalike } from "../src/detectors/separator-lookalike.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  scanSeparatorLookalike(input)[0]?.detail ?? "";

describe("J2 separator_lookalike — dot delimiters in the host", () => {
  it("ideographic full stop U+3002 (evil。com) is flagged", () => {
    const r = inspect("http://google。com");
    expect(r.reasons.map((x) => x.code)).toContain("separator_lookalike");
    expect(detail("http://google。com")).toContain("U+3002");
    expect(detail("http://google。com")).toContain("→ '.'");
  });

  it("fullwidth full stop U+FF0E", () => {
    expect(codes("http://paypal．com")).toContain("separator_lookalike");
  });

  it("halfwidth ideographic full stop U+FF61", () => {
    expect(codes("http://paypal｡com")).toContain("separator_lookalike");
  });

  it("one-dot leader U+2024", () => {
    expect(codes("http://paypal․com")).toContain("separator_lookalike");
  });

  it("works on a bare scheme-less host (no scheme gate)", () => {
    expect(codes("google。com")).toContain("separator_lookalike");
  });
});

describe("J2 separator_lookalike — slash delimiters in the authority", () => {
  it("division slash U+2215 path-looking lure (github.com∕x@evil.zip)", () => {
    const r = inspect("https://github.com∕x@evil.zip");
    expect(r.status).toBe("ok");
    expect(r.parsed?.effectiveHost).toBe("evil.zip");
    expect(r.reasons.map((x) => x.code)).toContain("separator_lookalike");
    expect(detail("https://github.com∕x@evil.zip")).toContain("→ '/'");
  });

  it("fullwidth solidus U+FF0F", () => {
    expect(codes("https://paypal.com／x@evil.com")).toContain("separator_lookalike");
  });

  it("contributes weight 0.5 (>= medium) — SC-1", () => {
    // A parseable slash-lure pushes the look-alike into userinfo, so
    // userinfo_present co-fires by construction; the registry weight (0.5,
    // medium band) is what guarantees the signal lands >= medium on its own.
    const r = inspect("https://example.com／a@host.example/");
    expect(r.reasons.map((x) => x.code)).toContain("separator_lookalike");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });
});

describe("J2 — emits one reason listing every offending character", () => {
  it("collapses multiple look-alikes into a single reason", () => {
    const r = inspect("http://a。b．c@evil.com");
    const hits = r.reasons.filter((x) => x.code === "separator_lookalike");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.detail).toContain("U+3002");
    expect(hits[0]!.detail).toContain("U+FF0E");
  });
});

describe("J2 — must not over-flag (SC-2)", () => {
  const benign = [
    "https://www.example.com/path",
    "https://example.jp/記事。html", // CJK full stop as punctuation IN THE PATH
    "https://example.com/a／b", // fullwidth solidus in the path, not authority
    "https://example.com:8443/x?y=1#z",
    "これは。テスト", // pure-CJK prose, no ASCII alnum in the would-be authority
    "https://пример.рф/тест", // legitimate Cyrillic IDN + path
  ];
  for (const input of benign) {
    it(`no separator_lookalike for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("separator_lookalike");
    });
  }
});

describe("J2 — scanSeparatorLookalike is total", () => {
  it("returns [] for empty / opaque / non-URL input", () => {
    for (const i of ["", "javascript:alert(1)", "mailto:a@b.com", "💥"]) {
      expect(scanSeparatorLookalike(i)).toEqual([]);
    }
  });
});
