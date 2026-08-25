import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * Cloud metadata endpoints named by HOSTNAME rather than by address
 * (LINK-hvawpgos).
 *
 * PIN FIRST. This file lands in two steps on purpose. As committed it records
 * the CURRENT behaviour — every vendor-documented metadata hostname scores
 * `0.00`/`info` with zero reasons, in both default and agent mode, while the
 * numeric spelling of the SAME endpoint scores `high` and blocks under
 * `agentMode`. The gap is not an opinion about wording; it is a measured
 * asymmetry, and pinning it before touching the detector is what makes the
 * follow-up commit's diff mean something.
 *
 * The IP-form assertions are pinned in the same file and must NOT move when the
 * hostname path lands. They are the control: a change that "fixes" hostnames by
 * disturbing the address table has broken more than it fixed.
 */

/** Vendor-documented ways to reach a cloud metadata service by NAME. */
const HOSTNAME_URLS = [
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "http://metadata.goog/computeMetadata/v1/instance/service-accounts/default/token",
  "http://metadata/computeMetadata/v1/instance/service-accounts/default/token",
  "http://instance-data/latest/meta-data/iam/security-credentials/",
  "http://metadata.azure.internal/metadata/instance?api-version=2021-02-01",
  "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
  "http://metadata.oraclecloud.com/opc/v2/instance/",
];

/**
 * Hostnames that must stay silent whatever happens above. Each one is a
 * near-miss of a real entry: an RFC 6761 special-use name that is NOT a
 * metadata endpoint (`svc.internal`), the metadata label in a subdomain
 * (`foo.metadata.example.com`), the metadata label under someone's own
 * registrable domain (`metadata.mycorp.com`), and the AWS legacy label as a
 * substring of a longer one (`my-instance-data.example.org`). A merely
 * internal-LOOKING hostname is not a metadata endpoint, and a detector that
 * cannot tell the difference is a blocklist.
 */
const BENIGN_URLS = [
  "http://svc.internal/",
  "http://foo.metadata.example.com/",
  "http://metadata.mycorp.com/",
  "http://my-instance-data.example.org/",
];

describe("cloud metadata hostnames — PINNED SILENCE (pre-change)", () => {
  for (const url of HOSTNAME_URLS) {
    it(`scores 0 / info / no reasons in default mode: ${url}`, () => {
      const r = inspect(url);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).toEqual([]);
    });

    it(`scores 0 / info / no reasons in agent mode: ${url}`, () => {
      const r = inspect(url, { agentMode: true });
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).toEqual([]);
    });
  }
});

describe("cloud metadata by ADDRESS — the control, must not move", () => {
  it("169.254.169.254 lands high with ip_cloud_metadata in default mode", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/");
    expect(r.score).toBe(0.75);
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toContain("ip_cloud_metadata");
    expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
  });

  it("169.254.169.254 blocks as critical under agentMode", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/", { agentMode: true });
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
    expect(r.reasons.map((x) => x.code)).toEqual(
      expect.arrayContaining(["ip_cloud_metadata", "ssrf_cloud_metadata"]),
    );
  });

  it("the detail names the provider, not a bare bucket", () => {
    const r = inspect("http://169.254.169.254/");
    const reason = r.reasons.find((x) => x.code === "ip_cloud_metadata");
    expect(reason?.detail).toContain("AWS / Azure / GCP / DigitalOcean / OpenStack");
  });
});

describe("internal-LOOKING hostnames stay silent", () => {
  for (const url of BENIGN_URLS) {
    it(`is benign in default mode: ${url}`, () => {
      const r = inspect(url);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    });

    it(`is benign in agent mode: ${url}`, () => {
      const r = inspect(url, { agentMode: true });
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
      expect(r.reasons.map((x) => x.code)).not.toContain("ip_cloud_metadata");
    });
  }
});
