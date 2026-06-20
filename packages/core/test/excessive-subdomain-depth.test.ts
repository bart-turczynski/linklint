import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "excessive_subdomain_depth")?.detail ?? "";

describe("I3 excessive_subdomain_depth — abnormally deep subdomain chain", () => {
  it("fires on a deep subdomain host (a.b.c.d.paypal.com.evil.tk → 6 labels)", () => {
    // Note: this input may also trip other detectors (embedded domain, risky
    // tld); we assert the I3 code specifically, not the exact reason set.
    // `evil.tk` is the registrable domain, so a/b/c/d/paypal/com = 6 subdomain
    // labels — well over the threshold of 5.
    const input = "https://a.b.c.d.paypal.com.evil.tk/";
    expect(codes(input)).toContain("excessive_subdomain_depth");
    expect(detail(input)).toContain("6");
    expect(detail(input)).toContain("evil.tk");
  });

  it("fires at exactly the threshold (5 subdomain labels)", () => {
    const input = "https://a.b.c.d.e.example.com/";
    expect(codes(input)).toContain("excessive_subdomain_depth");
    expect(detail(input)).toContain("5");
  });

  it("is scoring (carries a non-zero weight)", () => {
    const r = inspect("https://a.b.c.d.paypal.com.evil.tk/");
    const reason = r.reasons.find((x) => x.code === "excessive_subdomain_depth")!;
    expect(reason.weight).toBeGreaterThan(0);
    expect(reason.weight).toBeCloseTo(0.15, 5);
  });
});

describe("I3 excessive_subdomain_depth — must not over-flag (SC-2)", () => {
  const benign = [
    "https://cdn.assets.eu-west-1.example.com/", // 3 subdomain labels
    "https://sub.domain.example.co.uk/a/b", // 2 subdomain labels
    "https://www.example.com/", // 1 subdomain label
    "https://example.com", // 0 subdomain labels (bare registrable domain)
    "https://a.b.c.d.example.com/", // 4 subdomain labels — below threshold
    "http://127.0.0.1/", // IP host
  ];
  for (const input of benign) {
    it(`no excessive_subdomain_depth for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("excessive_subdomain_depth");
    });
  }
});
