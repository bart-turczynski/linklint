import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const reason = (input: string, code: string, opts?: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.find((r) => r.code === code);

describe("H3 policy — host allow/deny axis", () => {
  it("is inert when no policy option is passed", () => {
    const r = inspect("https://example.com/");
    expect(r.reasons.some((x) => x.layer === "policy")).toBe(false);
    expect(r.checksRun).toEqual(["lexical"]);
  });

  it("denyHosts emits host_denied (layer policy, weight 0) for a listed domain", () => {
    const r = inspect("https://evil.com/", { denyHosts: ["evil.com", "phishy.io"] });
    const hit = r.reasons.find((x) => x.code === "host_denied");
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain("evil.com");
    expect(r.checksRun).toContain("policy");
  });

  it("denyHosts also fires for a subdomain of a denied registrable domain", () => {
    const hit = reason("https://sub.evil.com/", "host_denied", { denyHosts: ["evil.com"] });
    expect(hit).toBeDefined();
    expect(hit!.detail).toContain("sub.evil.com");
    expect(hit!.detail).toContain("evil.com");
  });

  it("denyHosts does not fire for an unlisted domain", () => {
    expect(reason("https://example.com/", "host_denied", { denyHosts: ["evil.com"] })).toBeUndefined();
  });

  it("denyHosts is case-insensitive and tolerates a leading dot", () => {
    expect(reason("https://EVIL.com/", "host_denied", { denyHosts: [".Evil.COM"] })).toBeDefined();
  });

  it("allowHosts (default-deny) emits host_not_allowlisted for an unlisted host", () => {
    const hit = reason("https://example.org/", "host_not_allowlisted", { allowHosts: ["mycompany.com"] });
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain("example.org");
    expect(hit!.detail).toContain("mycompany.com");
  });

  it("allowHosts passes a listed host and its subdomains with no policy finding", () => {
    expect(reason("https://mycompany.com/", "host_not_allowlisted", { allowHosts: ["mycompany.com"] })).toBeUndefined();
    expect(reason("https://intra.mycompany.com/", "host_not_allowlisted", { allowHosts: ["mycompany.com"] })).toBeUndefined();
  });

  it("IP / hostless inputs produce no host policy findings", () => {
    const r = inspect("http://127.0.0.1/", { denyHosts: ["evil.com"], allowHosts: ["mycompany.com"] });
    expect(r.reasons.some((x) => x.layer === "policy")).toBe(false);
  });

  it("both axes fire independently when both configured", () => {
    const r = inspect("https://evil.com/", { denyHosts: ["evil.com"], allowHosts: ["mycompany.com"] });
    expect(r.reasons.some((x) => x.code === "host_denied")).toBe(true);
    expect(r.reasons.some((x) => x.code === "host_not_allowlisted")).toBe(true);
  });

  it("policy findings never move the score", () => {
    const base = inspect("https://example.org/").score;
    const withPolicy = inspect("https://example.org/", { allowHosts: ["mycompany.com"] }).score;
    expect(withPolicy).toBe(base);
  });
});
