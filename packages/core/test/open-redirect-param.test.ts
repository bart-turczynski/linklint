import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "open_redirect_param")?.detail ?? "";

describe("I2 open_redirect_param — cross-host redirect payload in a redirect param", () => {
  it("cross-host absolute redirect FIRES and names the target", () => {
    const r = inspect("https://example.com/login?next=https://evil.com/phish");
    expect(r.reasons.map((x) => x.code)).toContain("open_redirect_param");
    expect(detail(r.input)).toContain("evil.com");
    expect(detail(r.input)).toContain("example.com");
  });

  it("protocol-relative //evil.com FIRES", () => {
    expect(codes("https://example.com/?redirect=//evil.com/x")).toContain("open_redirect_param");
  });

  it("double-encoded cross-host value FIRES", () => {
    // https%3A%2F%2Fevil.com -> encode again -> %25...
    expect(codes("https://example.com/?url=https%253A%252F%252Fevil.com%252Fp")).toContain(
      "open_redirect_param",
    );
  });

  it("various redirect param names are matched (case-insensitive)", () => {
    expect(codes("https://example.com/?GoTo=https://evil.com")).toContain("open_redirect_param");
    expect(codes("https://example.com/?redirect_uri=https://evil.com")).toContain(
      "open_redirect_param",
    );
  });

  it("is medium-weight on its own (0.4)", () => {
    const r = inspect("https://example.com/login?next=https://evil.com/phish");
    expect(r.reasons.find((x) => x.code === "open_redirect_param")!.weight).toBeCloseTo(0.4, 5);
  });
});

describe("I2 open_redirect_param — must not over-flag (SC-2)", () => {
  const benign = [
    "https://example.com/?next=https://example.com/home", // same registrable domain
    "https://example.com/?next=https://app.example.com/home", // subdomain, same registrable domain
    "https://example.com/?next=/dashboard", // relative path, no host
    "https://example.com/?redirect=%2Fhome", // encoded relative path
    "https://example.com/?ref=https://evil.com", // non-redirect param carrying a URL
    "https://example.com/?url=2", // not URL-like
    "https://example.com/?next=", // empty value
    "https://example.com/", // no query
  ];
  for (const input of benign) {
    it(`no open_redirect_param for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("open_redirect_param");
    });
  }

  it("junk value does not throw and does not fire", () => {
    expect(() => inspect("https://example.com/?next=%%%not-a-url%%%")).not.toThrow();
    expect(codes("https://example.com/?next=%%%not-a-url%%%")).not.toContain("open_redirect_param");
  });
});
