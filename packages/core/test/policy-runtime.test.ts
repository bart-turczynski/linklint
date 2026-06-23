import { describe, expect, it } from "vitest";
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
