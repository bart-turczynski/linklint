import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const combosquatDetail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "brand_combosquat")?.detail ?? "";

describe("G3 brand_combosquat — brand keyword glued to an additive token in the host", () => {
  it("paypal-secure.com fires and names the brand + the offending label", () => {
    expect(codes("https://paypal-secure.com")).toContain("brand_combosquat");
    const d = combosquatDetail("https://paypal-secure.com");
    expect(d).toContain("paypal-secure");
    expect(d).toContain("paypal");
  });

  it("login-paypal.com fires (brand keyword on the right of the hyphen)", () => {
    expect(codes("https://login-paypal.com")).toContain("brand_combosquat");
    expect(combosquatDetail("https://login-paypal.com")).toContain("paypal");
  });

  it("secure-paypal-login.net fires (brand sandwiched between additive tokens)", () => {
    expect(codes("https://secure-paypal-login.net")).toContain("brand_combosquat");
    const d = combosquatDetail("https://secure-paypal-login.net");
    expect(d).toContain("secure-paypal-login");
    expect(d).toContain("paypal");
  });

  it("subdomain combosquat: paypal-verify.evil.com fires on the subdomain label", () => {
    expect(codes("https://paypal-verify.evil.com")).toContain("brand_combosquat");
    const d = combosquatDetail("https://paypal-verify.evil.com");
    expect(d).toContain("paypal-verify");
    expect(d).toContain("paypal");
  });

  it("carries the combosquat weight (0.4)", () => {
    const reason = inspect("https://paypal-secure.com").reasons.find(
      (x) => x.code === "brand_combosquat",
    )!;
    expect(reason.weight).toBeCloseTo(0.4, 5);
  });

  it("layer is lexical", () => {
    const reason = inspect("https://paypal-secure.com").reasons.find(
      (x) => x.code === "brand_combosquat",
    )!;
    expect(reason.layer).toBe("lexical");
  });
});

describe("G3 brand_combosquat — negatives that MUST stay quiet (SC-2)", () => {
  const benign = [
    "https://paypal.com/login", // the real brand, with its own keyword
    "https://login.paypal.com/", // brand subdomain — registrable is still paypal.com
    "https://s3.amazonaws.com/my-bucket", // concatenated legit token (no hyphen-glue)
    "https://my-blog.com/", // plain non-brand hyphenated domain
    "https://eu-west-1.example.com/", // hyphenated subdomain, no brand keyword
  ];
  for (const input of benign) {
    it(`no brand_combosquat for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("brand_combosquat");
    });
  }

  it("a lone brand keyword as a subdomain label does NOT fire (no hyphen-glue)", () => {
    // `paypal.evil.com` — brand keyword as a whole label, not combined within a
    // hyphenated label. That is embedded_domain / brand_in_path territory.
    expect(codes("https://paypal.evil.com/")).not.toContain("brand_combosquat");
  });

  it("does not fire on an IP host", () => {
    expect(codes("http://127.0.0.1/")).not.toContain("brand_combosquat");
    expect(codes("http://2130706433/")).not.toContain("brand_combosquat");
  });

  it("does not fire on empty / unparseable input", () => {
    expect(codes("")).not.toContain("brand_combosquat");
    expect(codes("   ")).not.toContain("brand_combosquat");
  });
});
