import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { normalizePolicyOptions } from "../src/parse/runtime.js";

describe("policy runtime config", () => {
  it("normalizes policy option lists once into ordered values and membership sets", () => {
    const policy = normalizePolicyOptions({
      denyTlds: [".RU", "Cn"],
      allowTlds: ["COM"],
      denyHosts: [".Evil.COM"],
      allowHosts: ["MyCompany.COM"],
      denySchemes: ["FTP:", ":DATA:"],
      allowSchemes: ["HTTPS"],
      denyPorts: [8080, 31337],
      denyNonStandardPorts: true,
    });

    expect(policy.denyTlds.values).toEqual(["ru", "cn"]);
    expect(policy.denyTlds.set.has("ru")).toBe(true);
    expect(policy.allowTlds.values).toEqual(["com"]);
    expect(policy.denyHosts.values).toEqual(["evil.com"]);
    expect(policy.denyHosts.set.has("evil.com")).toBe(true);
    expect(policy.allowHosts.values).toEqual(["mycompany.com"]);
    expect(policy.denySchemes.values).toEqual(["ftp", "data"]);
    expect(policy.denySchemes.set.has("ftp")).toBe(true);
    expect(policy.allowSchemes.values).toEqual(["https"]);
    expect(policy.denyPorts.values).toEqual([8080, 31337]);
    expect(policy.denyPorts.set.has(8080)).toBe(true);
    expect(policy.denyNonStandardPorts).toBe(true);
  });

  it("preserves configured state separately from normalized list length", () => {
    const policy = normalizePolicyOptions({ allowTlds: [] });

    expect(policy.allowTlds.configured).toBe(true);
    expect(policy.allowTlds.values).toEqual([]);
    expect(policy.denyTlds.configured).toBe(false);
  });
});

// LINK-uxkrtcnw: policy list entries are trimmed at the normalizedList() choke
// point, so every axis inherits it. Building a list by splitting a config
// string used to leave a silently void policy — no error, no warning, exit 0.
describe("policy runtime config — surrounding whitespace is trimmed", () => {
  it("strips surrounding whitespace on every string axis, so membership hits", () => {
    const policy = normalizePolicyOptions({
      denyTlds: [" com"],
      allowTlds: ["com "],
      denyHosts: [" evil.com"],
      allowHosts: ["mycompany.com "],
      denySchemes: [" https"],
      allowSchemes: ["https "],
    });

    expect(policy.denyTlds.values).toEqual(["com"]);
    expect(policy.denyTlds.set.has("com")).toBe(true);
    expect(policy.allowTlds.set.has("com")).toBe(true);
    expect(policy.denyHosts.set.has("evil.com")).toBe(true);
    expect(policy.allowHosts.set.has("mycompany.com")).toBe(true);
    expect(policy.denySchemes.set.has("https")).toBe(true);
    expect(policy.allowSchemes.set.has("https")).toBe(true);
  });

  it("tolerates tabs and newlines, not just spaces", () => {
    const policy = normalizePolicyOptions({ denyTlds: ["\tru\n"], denySchemes: [" \tftp: "] });

    expect(policy.denyTlds.set.has("ru")).toBe(true);
    expect(policy.denySchemes.set.has("ftp")).toBe(true);
  });

  it("splitting a config string on ',' keeps every entry live", () => {
    const policy = normalizePolicyOptions({ denyTlds: "com, ru".split(",") });

    expect(policy.denyTlds.values).toEqual(["com", "ru"]);
    expect(policy.denyTlds.set.has("com")).toBe(true);
    expect(policy.denyTlds.set.has("ru")).toBe(true);
  });

  it("trims before the leading-dot strip on the tld/host axes", () => {
    const policy = normalizePolicyOptions({ denyTlds: [" .ru"], denyHosts: [" .evil.com"] });

    expect(policy.denyTlds.values).toEqual(["ru"]);
    expect(policy.denyHosts.values).toEqual(["evil.com"]);
  });

  // Empty-after-trim DROPS rather than throwing: normalizeOptions is
  // contractually total, and an empty string could never match an axis key
  // anyway. See the normalizedList doc comment for the full rationale.
  it("drops an entry that is empty after trimming, keeping its neighbours", () => {
    const policy = normalizePolicyOptions({ denyTlds: ["  ", "com", ""], denySchemes: [":", "ftp"] });

    expect(policy.denyTlds.values).toEqual(["com"]);
    expect(policy.denyTlds.set.has("")).toBe(false);
    expect(policy.denySchemes.values).toEqual(["ftp"]);
  });

  it("an all-blank allow-list stays configured, so it fails CLOSED", () => {
    const policy = normalizePolicyOptions({ allowTlds: ["  "] });

    expect(policy.allowTlds.configured).toBe(true);
    expect(policy.allowTlds.values).toEqual([]);

    const r = inspect("https://example.com/", { allowTlds: ["  "] });
    expect(r.reasons.some((x) => x.code === "tld_not_allowlisted")).toBe(true);
  });

  it("end to end: a padded deny entry now emits its policy reason", () => {
    const r = inspect("https://a.example.com/", { denyTlds: [" com"] });
    const hit = r.reasons.find((x) => x.code === "tld_denied");

    expect(hit).toBeDefined();
    expect(hit!.layer).toBe("policy");
    expect(hit!.weight).toBe(0);
    expect(hit!.detail).toContain(".com");
  });

  it("end to end: a padded entry on each remaining axis fires", () => {
    expect(
      inspect("https://a.evil.com/", { denyHosts: [" evil.com "] }).reasons.some(
        (x) => x.code === "host_denied",
      ),
    ).toBe(true);
    expect(
      inspect("ftp://example.com/", { denySchemes: [" ftp "] }).reasons.some(
        (x) => x.code === "scheme_denied",
      ),
    ).toBe(true);
    expect(
      inspect("https://example.com/", { allowHosts: [" example.com "] }).reasons.some(
        (x) => x.code === "host_not_allowlisted",
      ),
    ).toBe(false);
    expect(
      inspect("https://example.com/", { allowSchemes: [" https "] }).reasons.some(
        (x) => x.code === "scheme_denied",
      ),
    ).toBe(false);
  });
});
