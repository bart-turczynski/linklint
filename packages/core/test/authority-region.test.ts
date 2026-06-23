import { describe, expect, it } from "vitest";
import { authorityRegion } from "../src/parse/authority-region.js";

describe("authorityRegion — raw tokenizer projection", () => {
  it("preserves backslash authority introducers for structural scans", () => {
    expect(authorityRegion("http:\\\\google.com")).toMatchObject({
      scheme: "http",
      protocolRelative: false,
      separator: "\\\\",
      authority: "google.com",
      path: "",
      fragment: null,
      opaque: false,
    });
  });

  it("preserves slash-confusion introducers separately from the authority", () => {
    expect(authorityRegion("http:///google.com")).toMatchObject({
      scheme: "http",
      separator: "///",
      authority: "google.com",
      path: "",
    });
  });

  it("scopes separator lookalikes to the raw authority token", () => {
    expect(authorityRegion("https://example.com/a／b?next=paypal。com")).toMatchObject({
      scheme: "https",
      separator: "//",
      authority: "example.com",
      path: "/a／b",
      fragment: null,
    });
  });

  it("keeps opaque schemes hostless", () => {
    expect(authorityRegion("javascript:alert(1)")).toMatchObject({
      scheme: "javascript",
      separator: "",
      authority: "",
      path: "alert(1)",
      opaque: true,
    });
  });
});
