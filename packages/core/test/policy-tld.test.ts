import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const reason = (input: string, code: string, opts?: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.find((r) => r.code === code);

describe("H2 policy — TLD allow/deny axis", () => {
  it("is inert when no policy option is passed", () => {
    const r = inspect("https://example.com/");
    expect(r.reasons.some((x) => x.layer === "policy")).toBe(false);
    expect(r.checksRun).toEqual(["lexical"]);
  });

  it("denyTlds emits tld_denied (layer policy, weight 0) for a listed TLD", () => {
    const r = inspect("https://promo.ru/", { denyTlds: ["ru", "cn"] });
    const hit = r.reasons.find((x) => x.code === "tld_denied");
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain(".ru");
    expect(r.checksRun).toContain("policy");
  });

  it("denyTlds does not fire for an unlisted TLD", () => {
    expect(reason("https://example.com/", "tld_denied", { denyTlds: ["ru"] })).toBeUndefined();
  });

  it("allowTlds (default-deny) emits tld_not_allowlisted when TLD is not listed", () => {
    const hit = reason("https://example.org/", "tld_not_allowlisted", { allowTlds: ["com", "de"] });
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain(".org");
    expect(hit!.detail).toContain("com");
  });

  it("allowTlds passes a listed TLD with no policy finding", () => {
    expect(reason("https://example.com/", "tld_not_allowlisted", { allowTlds: ["com"] })).toBeUndefined();
  });

  it("matches the last public-suffix label (co.uk → uk) and is case-insensitive", () => {
    expect(reason("https://shop.co.uk/", "tld_denied", { denyTlds: [".UK"] })).toBeDefined();
  });

  it("IP / hostless inputs produce no TLD policy findings", () => {
    const r = inspect("http://127.0.0.1/", { denyTlds: ["ru"], allowTlds: ["com"] });
    expect(r.reasons.some((x) => x.layer === "policy")).toBe(false);
  });

  it("both axes fire independently when both configured", () => {
    const r = inspect("https://promo.ru/", { denyTlds: ["ru"], allowTlds: ["com"] });
    expect(r.reasons.some((x) => x.code === "tld_denied")).toBe(true);
    expect(r.reasons.some((x) => x.code === "tld_not_allowlisted")).toBe(true);
  });

  it("policy findings never move the score", () => {
    const base = inspect("https://example.org/").score;
    const withPolicy = inspect("https://example.org/", { allowTlds: ["com"] }).score;
    expect(withPolicy).toBe(base);
  });
});
