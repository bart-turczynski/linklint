import { describe, expect, it } from "vitest";
import { parse } from "../src/parse/parse.js";

describe("parse — full URLs", () => {
  it("parses scheme, host, port, path, query, fragment", () => {
    const ctx = parse("https://www.example.com:8443/a/b?x=1&y=2#frag");
    expect(ctx).not.toBeNull();
    expect(ctx!.scheme).toBe("https");
    expect(ctx!.host).toBe("www.example.com");
    expect(ctx!.port).toBe(8443);
    expect(ctx!.path).toBe("/a/b");
    expect(ctx!.query).toBe("x=1&y=2");
    expect(ctx!.fragment).toBe("frag");
    expect(ctx!.registrableDomain).toBe("example.com");
  });

  it("captures userinfo and the real host (last @)", () => {
    const ctx = parse("https://paypal.com@evil.com/login");
    expect(ctx!.userinfo).toBe("paypal.com");
    expect(ctx!.host).toBe("evil.com");
    expect(ctx!.path).toBe("/login");
  });
});

describe("parse — bare hosts / missing scheme", () => {
  it("accepts a bare hostname", () => {
    const ctx = parse("example.com");
    expect(ctx!.scheme).toBeNull();
    expect(ctx!.host).toBe("example.com");
    expect(ctx!.registrableDomain).toBe("example.com");
  });

  it("treats host:port without scheme as host+port, not scheme", () => {
    const ctx = parse("example.com:8080/x");
    expect(ctx!.scheme).toBeNull();
    expect(ctx!.host).toBe("example.com");
    expect(ctx!.port).toBe(8080);
    expect(ctx!.path).toBe("/x");
  });

  it("tolerates trailing whitespace", () => {
    const ctx = parse("  https://example.com/  ");
    expect(ctx!.host).toBe("example.com");
  });
});

describe("parse — opaque/dangerous schemes", () => {
  it("parses javascript: as an opaque scheme with no host", () => {
    const ctx = parse("javascript:alert(1)");
    expect(ctx!.scheme).toBe("javascript");
    expect(ctx!.host).toBe("");
    expect(ctx!.parsed.effectiveHost).toBeNull();
    expect(ctx!.path).toBe("alert(1)");
  });

  it("parses data: URLs", () => {
    const ctx = parse("data:text/html,<script>");
    expect(ctx!.scheme).toBe("data");
    expect(ctx!.parsed.effectiveHost).toBeNull();
  });
});

describe("parse — hostless local file: forms (V2 dangerous-scheme coverage)", () => {
  // `file:/etc/passwd` and `file:///etc/passwd` are the WHATWG-canonical local
  // (hostless) file shapes. They must parse to scheme:file + host:none + path so
  // the dangerous_scheme detector fires — they previously slipped through as
  // `invalid` (parse_error / ambiguous_authority), the local-file-read bypass.
  it("parses file:/path as hostless with the path preserved", () => {
    const ctx = parse("file:/etc/passwd");
    expect(ctx).not.toBeNull();
    expect(ctx!.scheme).toBe("file");
    expect(ctx!.host).toBe("");
    expect(ctx!.parsed.effectiveHost).toBeNull();
    expect(ctx!.path).toBe("/etc/passwd");
  });

  it("parses file:///path (explicit empty authority) as hostless", () => {
    const ctx = parse("file:///etc/passwd");
    expect(ctx).not.toBeNull();
    expect(ctx!.scheme).toBe("file");
    expect(ctx!.host).toBe("");
    expect(ctx!.parsed.effectiveHost).toBeNull();
    expect(ctx!.path).toBe("/etc/passwd");
  });

  it("leaves file://host/path with a non-empty authority on the host path", () => {
    const ctx = parse("file://localhost/etc/passwd");
    expect(ctx!.scheme).toBe("file");
    expect(ctx!.host).toBe("localhost");
    expect(ctx!.path).toBe("/etc/passwd");
  });
});

describe("parse — malformed input returns null (never throws)", () => {
  const garbage = [
    "",
    "   ",
    "ht!tp://%%%not a url",
    "http://",
    "http:// space.com",
    "<<<>>>",
    "@@@",
    "http://exa mple.com",
    // The hostless file: special-case must not swallow genuinely-malformed
    // file: input: a non-empty authority with whitespace still parses invalid.
    "file:// /etc/passwd",
  ];
  for (const g of garbage) {
    it(`returns null for ${JSON.stringify(g)}`, () => {
      expect(() => parse(g)).not.toThrow();
      expect(parse(g)).toBeNull();
    });
  }
});
