import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const reason = (input: string, code: string, opts?: Parameters<typeof inspect>[1]) =>
  inspect(input, opts).reasons.find((r) => r.code === code);

describe("H4 policy — scheme & port axes", () => {
  it("is inert when no policy option is passed", () => {
    const r = inspect("https://example.com:8080/");
    expect(r.reasons.some((x) => x.layer === "policy")).toBe(false);
    expect(r.checksRun).toEqual(["lexical"]);
  });

  it("allowSchemes (https-only) emits scheme_denied for http and passes https", () => {
    const hit = reason("http://example.com/", "scheme_denied", { allowSchemes: ["https"] });
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain("http");
    expect(hit!.detail).toContain("allow-list");
    expect(inspect("http://example.com/", { allowSchemes: ["https"] }).checksRun).toContain("policy");

    expect(reason("https://example.com/", "scheme_denied", { allowSchemes: ["https"] })).toBeUndefined();
  });

  it("denySchemes blocks a listed scheme and is case-insensitive / colon-tolerant", () => {
    const hit = reason("ftp://example.com/", "scheme_denied", { denySchemes: ["FTP:"] });
    expect(hit).toBeDefined();
    expect(hit!.detail).toContain("deny-list");
    expect(reason("https://example.com/", "scheme_denied", { denySchemes: ["ftp"] })).toBeUndefined();
  });

  it("scheme axis is skipped when there is no scheme (allow-list does not fire)", () => {
    const r = inspect("example.com/path", { allowSchemes: ["https"] });
    expect(r.parsed?.scheme).toBeNull();
    expect(r.reasons.some((x) => x.code === "scheme_denied")).toBe(false);
  });

  it("denyPorts emits port_denied (layer policy, weight 0) for a listed port", () => {
    const hit = reason("https://example.com:8080/", "port_denied", { denyPorts: [8080, 31337] });
    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain("8080");
    expect(hit!.detail).toContain("deny-list");
  });

  it("denyPorts does not fire for an unlisted port", () => {
    expect(reason("https://example.com:8443/", "port_denied", { denyPorts: [8080] })).toBeUndefined();
  });

  it("denyNonStandardPorts flags :8080 on https but not the standard :443", () => {
    const hit = reason("https://example.com:8080/", "port_denied", { denyNonStandardPorts: true });
    expect(hit).toBeDefined();
    expect(hit!.detail).toContain("non-standard");
    expect(hit!.detail).toContain("443");

    expect(reason("https://example.com:443/", "port_denied", { denyNonStandardPorts: true })).toBeUndefined();
  });

  it("port axis is skipped when no explicit port is present", () => {
    expect(reason("https://example.com/", "port_denied", { denyNonStandardPorts: true, denyPorts: [443] })).toBeUndefined();
  });

  it("emits at most one port_denied when both port conditions hit (deny-list wins)", () => {
    const r = inspect("https://example.com:8080/", { denyPorts: [8080], denyNonStandardPorts: true });
    const hits = r.reasons.filter((x) => x.code === "port_denied");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.detail).toContain("deny-list");
  });

  it("scheme and port axes fire independently when both configured", () => {
    const r = inspect("ftp://example.com:8080/", { denySchemes: ["ftp"], denyPorts: [8080] });
    expect(r.reasons.some((x) => x.code === "scheme_denied")).toBe(true);
    expect(r.reasons.some((x) => x.code === "port_denied")).toBe(true);
  });

  it("policy findings never move the score", () => {
    const base = inspect("http://example.com:8080/").score;
    const withPolicy = inspect("http://example.com:8080/", {
      allowSchemes: ["https"],
      denyNonStandardPorts: true,
    }).score;
    expect(withPolicy).toBe(base);
  });
});
