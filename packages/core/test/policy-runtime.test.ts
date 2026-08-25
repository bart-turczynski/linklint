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

// PIN (LINK-uxkrtcnw): policy list entries are NOT trimmed. Every axis routes
// through normalizedList(), and none of the per-axis normalizers strips
// whitespace, so a list built the natural way — env.DENY_TLDS.split(",") — is
// silently void. This block pins the fail-open AS a fail-open, so the fix has to
// move it deliberately rather than by accident.
describe("policy runtime config — untrimmed entries (pinned fail-open)", () => {
  it("keeps surrounding whitespace on every string axis, so membership misses", () => {
    const policy = normalizePolicyOptions({
      denyTlds: [" com"],
      allowTlds: ["com "],
      denyHosts: [" evil.com"],
      allowHosts: ["mycompany.com "],
      denySchemes: [" https"],
      allowSchemes: ["https "],
    });

    expect(policy.denyTlds.values).toEqual([" com"]);
    expect(policy.denyTlds.set.has("com")).toBe(false);
    expect(policy.allowTlds.set.has("com")).toBe(false);
    expect(policy.denyHosts.set.has("evil.com")).toBe(false);
    expect(policy.allowHosts.set.has("mycompany.com")).toBe(false);
    expect(policy.denySchemes.set.has("https")).toBe(false);
    expect(policy.allowSchemes.set.has("https")).toBe(false);
  });

  it("splitting a config string on ',' voids every entry after the first", () => {
    const policy = normalizePolicyOptions({ denyTlds: "com, ru".split(",") });

    expect(policy.denyTlds.values).toEqual(["com", " ru"]);
    expect(policy.denyTlds.set.has("com")).toBe(true);
    expect(policy.denyTlds.set.has("ru")).toBe(false);
  });

  it("leading whitespace defeats the leading-dot strip on the tld/host axes", () => {
    const policy = normalizePolicyOptions({ denyTlds: [" .ru"], denyHosts: [" .evil.com"] });

    expect(policy.denyTlds.values).toEqual([" .ru"]);
    expect(policy.denyHosts.values).toEqual([" .evil.com"]);
  });

  it("a whitespace-only entry survives as a dead member of the matching set", () => {
    const policy = normalizePolicyOptions({ denyTlds: ["  ", "com"] });

    expect(policy.denyTlds.values).toEqual(["  ", "com"]);
    expect(policy.denyTlds.set.has("  ")).toBe(true);
  });

  it("end to end: a padded deny entry emits no policy reason at all", () => {
    const r = inspect("https://a.example.com/", { denyTlds: [" com"] });

    expect(r.reasons.some((x) => x.code === "tld_denied")).toBe(false);
    expect(r.reasons.filter((x) => x.layer === "policy")).toEqual([]);
    expect(r.checksRun).toContain("policy");
  });
});
