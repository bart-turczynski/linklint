import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "file_extension_tld")?.detail ?? "";

describe("J6 file_extension_tld — filename masquerade", () => {
  it("bare invoice.zip reads as a filename and flags", () => {
    expect(codes("https://invoice.zip/")).toContain("file_extension_tld");
    expect(detail("https://invoice.zip/")).toContain("invoice.zip");
    expect(detail("https://invoice.zip/")).toContain(".zip");
  });

  it("bare setup.mov flags", () => {
    expect(codes("https://setup.mov")).toContain("file_extension_tld");
  });

  it("a subdomained .zip host hidden behind userinfo flags via the userinfo branch", () => {
    const r = inspect("https://paypal.com@cdn.update.zip/");
    expect(r.parsed?.effectiveHost).toBe("cdn.update.zip");
    expect(r.reasons.map((x) => x.code)).toContain("file_extension_tld");
    expect(detail(r.input)).toContain("userinfo");
  });

  it("plain userinfo + bare .zip host flags (bare-filename branch)", () => {
    expect(codes("https://user@download.zip/")).toContain("file_extension_tld");
  });

  it("scores >= medium on its own (weight 0.4) and never co-fires with risky_tld", () => {
    const r = inspect("https://invoice.zip/");
    expect(["medium", "high", "critical"]).toContain(r.severity);
    expect(r.reasons.map((x) => x.code)).not.toContain("risky_tld");
  });

  it("combines with the J2 slash-look-alike lure to land high", () => {
    const r = inspect("https://github.com∕x@evil.zip");
    const found = r.reasons.map((x) => x.code);
    expect(found).toContain("separator_lookalike");
    expect(found).toContain("file_extension_tld");
    expect(["high", "critical"]).toContain(r.severity);
  });
});

describe("J6 file_extension_tld — must not over-flag (SC-2)", () => {
  const benign = [
    "https://www.example.com/archive.zip", // .zip in the PATH (a real file), not the TLD
    "https://example.com/downloads/setup.mov",
    "https://cdn.assets.acme.zip/", // deep-subdomain .zip with no userinfo reads as a site
    "https://github.com/user/repo/archive/main.zip",
    "https://example.com/", // ordinary TLD
  ];
  for (const input of benign) {
    it(`no file_extension_tld for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("file_extension_tld");
    });
  }
});
