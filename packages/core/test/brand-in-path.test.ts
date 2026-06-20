import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_in_path")?.detail ?? "";

describe("J7 brand_in_path — brand planted in the path of an unrelated host", () => {
  it("domain-shaped: evil.com/paypal.com/login flags and names the real host", () => {
    const r = inspect("https://evil.com/paypal.com/login");
    expect(r.reasons.map((x) => x.code)).toContain("brand_in_path");
    expect(detail(r.input)).toContain("evil.com");
    expect(detail(r.input)).toContain("paypal.com");
  });

  it("domain-shaped in a query value (?next=netflix.com)", () => {
    expect(codes("https://x.co/?next=netflix.com")).toContain("brand_in_path");
  });

  it("credential flow: evil.com/paypal/login flags", () => {
    expect(codes("https://evil.com/paypal/login")).toContain("brand_in_path");
    expect(detail("https://evil.com/paypal/login")).toContain("credential-flow");
  });

  it("credential flow: phish.io/google/signin", () => {
    expect(codes("https://phish.io/google/signin")).toContain("brand_in_path");
  });

  it("is low-weight on its own (0.2)", () => {
    const r = inspect("https://evil.com/paypal.com/login");
    expect(r.severity).toBe("low");
    expect(r.score).toBeCloseTo(0.2, 5);
  });

  it("is distinct from the info-only confusable_in_path", () => {
    const r = inspect("https://evil.com/paypal/login");
    const found = r.reasons.map((x) => x.code);
    expect(found).toContain("brand_in_path");
    // brand_in_path is scoring; confusable_in_path (if present) is weight 0
    expect(r.reasons.find((x) => x.code === "brand_in_path")!.weight).toBeGreaterThan(0);
  });
});

describe("J7 brand_in_path — must not over-flag (SC-2)", () => {
  const benign = [
    "https://paypal.com/login", // the brand's own site
    "https://www.paypal.com/us/signin",
    "https://github.com/paypal/repo", // bare brand, no credential context
    "https://medium.com/paypal-vs-stripe", // not an exact token, not domain-shaped
    "https://amazon.com/dp/B001", // brand's own commerce path
    "https://example.com/blog/2024/netflix-review", // brand word in prose, not a token
    "https://en.wikipedia.org/wiki/PayPal",
    "https://docs.stripe.com/payments", // brand in host, guarded
    "https://example.com/", // no path tokens
  ];
  for (const input of benign) {
    it(`no brand_in_path for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("brand_in_path");
    });
  }
});

describe("J7 — data version is stamped", () => {
  it("exposes a brands data version", () => {
    expect(inspect("https://example.com/").dataVersions.brands).toBeTruthy();
  });
});
