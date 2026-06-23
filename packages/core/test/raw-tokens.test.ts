import { describe, expect, it } from "vitest";
import { tokenizeRawUrl } from "../src/parse/raw-tokens.js";

describe("raw URL tokenizer — component boundaries", () => {
  it("records full URL tokens without validating the host", () => {
    expect(tokenizeRawUrl("HTTPS://www.example.com:8443/a/b?x=1&y=2#frag")).toMatchObject({
      prepared: "HTTPS://www.example.com:8443/a/b?x=1&y=2#frag",
      rawScheme: "HTTPS",
      scheme: "https",
      schemeDelimiter: ":",
      authorityIntroducer: "//",
      authority: "www.example.com:8443",
      path: "/a/b",
      query: "x=1&y=2",
      fragment: "frag",
      opaque: false,
      protocolRelative: false,
    });
  });

  it("keeps hostless file: forms hostless while preserving their path tokens", () => {
    expect(tokenizeRawUrl("file:/etc/passwd")).toMatchObject({
      scheme: "file",
      authorityIntroducer: "",
      authority: "",
      path: "/etc/passwd",
    });
    expect(tokenizeRawUrl("file:///etc/passwd")).toMatchObject({
      scheme: "file",
      authorityIntroducer: "//",
      authority: "",
      path: "/etc/passwd",
    });
    expect(tokenizeRawUrl("file://localhost/etc/passwd")).toMatchObject({
      scheme: "file",
      authorityIntroducer: "//",
      authority: "localhost",
      path: "/etc/passwd",
    });
  });

  it("does not validate malformed file: authorities", () => {
    expect(tokenizeRawUrl("file:// /etc/passwd")).toMatchObject({
      scheme: "file",
      authorityIntroducer: "//",
      authority: " ",
      path: "/etc/passwd",
    });
  });

  it("records opaque scheme bodies without an authority", () => {
    expect(tokenizeRawUrl("javascript:alert(1)")).toMatchObject({
      scheme: "javascript",
      authorityIntroducer: "",
      authority: "",
      path: "alert(1)",
      query: null,
      fragment: null,
      opaque: true,
    });
    expect(tokenizeRawUrl("data:text/html,<script>?x=1#frag")).toMatchObject({
      scheme: "data",
      authority: "",
      path: "text/html,<script>",
      query: "x=1",
      fragment: "frag",
      opaque: true,
    });
    expect(tokenizeRawUrl("mailto:a@b.com")).toMatchObject({
      scheme: "mailto",
      authority: "",
      path: "a@b.com",
      opaque: true,
    });
  });

  it("extracts query and fragment without letting them leak into the authority", () => {
    expect(tokenizeRawUrl("https://example.com/a?x=1#frag")).toMatchObject({
      authority: "example.com",
      path: "/a",
      query: "x=1",
      fragment: "frag",
    });
    expect(tokenizeRawUrl("http://google.com#@evil.com/")).toMatchObject({
      authority: "google.com",
      path: "",
      query: null,
      fragment: "@evil.com/",
    });
  });

  it("keeps bare host:port inputs as authority, not scheme", () => {
    expect(tokenizeRawUrl("example.com:8080/x")).toMatchObject({
      rawScheme: null,
      scheme: null,
      schemeDelimiter: null,
      authority: "example.com:8080",
      path: "/x",
    });
    expect(tokenizeRawUrl("google.com:8080/x")).toMatchObject({
      scheme: null,
      authority: "google.com:8080",
      path: "/x",
    });
  });
});

describe("raw URL tokenizer — parser-differential surfaces", () => {
  it("preserves ambiguous authority tokens without host validation", () => {
    const cases = [
      ["http://foo@evil.com:80@google.com/", "foo@evil.com:80@google.com", "/"],
      ["http://foo@127.0.0.1 @google.com:11211/", "foo@127.0.0.1 @google.com:11211", "/"],
      ["http://127.0.0.1:11211:80/", "127.0.0.1:11211:80", "/"],
      ["http://good.com\\@evil.com", "good.com\\@evil.com", ""],
    ] as const;

    for (const [input, authority, path] of cases) {
      expect(tokenizeRawUrl(input)).toMatchObject({
        scheme: "http",
        authorityIntroducer: "//",
        authority,
        path,
      });
    }
  });

  it("records slash and backslash introducers for later structural scans", () => {
    expect(tokenizeRawUrl("http:\\\\google.com")).toMatchObject({
      scheme: "http",
      authorityIntroducer: "\\\\",
      authority: "google.com",
      path: "",
    });
    expect(tokenizeRawUrl("http:///google.com")).toMatchObject({
      scheme: "http",
      authorityIntroducer: "///",
      authority: "google.com",
      path: "",
    });
    expect(tokenizeRawUrl("//evil.com")).toMatchObject({
      scheme: null,
      protocolRelative: true,
      authorityIntroducer: "//",
      authority: "evil.com",
      path: "",
    });
  });

  it("keeps separator lookalikes scoped to the raw authority token", () => {
    expect(tokenizeRawUrl("http://paypal。com")).toMatchObject({
      authority: "paypal。com",
      path: "",
    });
    expect(tokenizeRawUrl("https://paypal.com／x@evil.com")).toMatchObject({
      authority: "paypal.com／x@evil.com",
      path: "",
    });
    expect(tokenizeRawUrl("https://example.com/a／b?next=paypal。com")).toMatchObject({
      authority: "example.com",
      path: "/a／b",
      query: "next=paypal。com",
    });
  });

  it("tokenizes malformed inputs without throwing or normalizing them", () => {
    const cases = [
      ["", ""],
      ["   ", "   "],
      ["ht!tp://%%%not a url", "ht!tp:"],
      ["http://", ""],
      ["http:// space.com", " space.com"],
      ["<<<>>>", "<<<>>>"],
      ["@@@", "@@@"],
      ["http://exa mple.com", "exa mple.com"],
    ] as const;

    for (const [input, authority] of cases) {
      expect(() => tokenizeRawUrl(input)).not.toThrow();
      expect(tokenizeRawUrl(input).authority).toBe(authority);
    }
  });
});
