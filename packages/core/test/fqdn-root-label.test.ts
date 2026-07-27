import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (url: string) => inspect(url).reasons.map((r) => r.code);

describe("V7 fqdn_root_label — the explicit DNS root label (LINK-fboctpse)", () => {
  it("fires on a single trailing dot", () => {
    expect(codes("https://example.com./")).toContain("fqdn_root_label");
  });

  it("fires with a port present", () => {
    expect(codes("https://example.com.:443/")).toContain("fqdn_root_label");
  });

  it("fires on a subdomain host", () => {
    expect(codes("https://sub.example.com./")).toContain("fqdn_root_label");
  });

  it("stays silent on the bare form", () => {
    expect(codes("https://example.com/")).not.toContain("fqdn_root_label");
  });

  it("stays silent on IP literals", () => {
    expect(codes("https://93.184.216.34/")).not.toContain("fqdn_root_label");
    expect(codes("https://[2606:2800:220:1:248:1893:25c8:1946]/")).not.toContain("fqdn_root_label");
  });

  // Pins guarantee C8. The doc says two or more trailing dots "never reach this
  // check" — that holds because they create an empty label and are rejected at
  // parse time, not because the detector filters them. If parsing ever starts
  // accepting them, this fails rather than the claim silently going stale.
  it("never reaches the check for two or more trailing dots — they fail parsing first", () => {
    for (const url of ["https://example.com../", "https://example.com.../"]) {
      const result = inspect(url);
      expect(result.status, url).toBe("invalid");
      expect(result.reasons.map((r) => r.code), url).toContain("parse_error");
      expect(result.reasons.map((r) => r.code), url).not.toContain("fqdn_root_label");
    }
  });

  it("annotates without scoring: the verdict stays 0.00/info", () => {
    const result = inspect("https://example.com./");
    expect(result.score).toBe(0);
    expect(result.severity).toBe("info");
    expect(result.reasons.find((r) => r.code === "fqdn_root_label")!.weight).toBe(0);
  });

  // The proposed home was ambiguous_authority (0.65) and was rejected because
  // parsers do not disagree on this host. Pinned so a future change has to argue
  // with the decision rather than quietly land it.
  it("does not emit ambiguous_authority", () => {
    expect(codes("https://example.com./")).not.toContain("ambiguous_authority");
  });

  describe("linklint's own policy layer is not bypassed by the root label", () => {
    it("matches an allow-list entry written in bare form", () => {
      const result = inspect("https://example.com./", { allowHosts: ["example.com"] });
      expect(result.reasons.map((r) => r.code)).not.toContain("host_not_allowlisted");
    });

    it("still refuses a host that is not on the allow-list", () => {
      const result = inspect("https://evil.com./", { allowHosts: ["example.com"] });
      expect(result.reasons.map((r) => r.code)).toContain("host_not_allowlisted");
    });

    it("still denies a deny-listed host written in FQDN form", () => {
      const result = inspect("https://evil.com./", { denyHosts: ["evil.com"] });
      expect(result.reasons.map((r) => r.code)).toContain("host_denied");
    });
  });
});
