import { describe, expect, it } from "vitest";

import {
  normalizeTlsCertificate,
  TlsCertificateAnalysisError,
} from "../src/transport/tls-certificate.js";
import { readCertificatePolicyOids, DerParseError } from "../src/transport/tls-der.js";
import {
  certificateDer,
  handshake,
  type TlsCertificateFixture,
} from "./fixtures/tls-certificates.js";

const OBSERVED_AT = new Date("2026-01-01T00:00:00.000Z");

function normalize(
  leaf: TlsCertificateFixture,
  overrides: Parameters<typeof handshake>[1] = {},
  hostname = "example.com",
) {
  return normalizeTlsCertificate(handshake(leaf, overrides), { hostname, observedAt: OBSERVED_AT });
}

describe("readCertificatePolicyOids", () => {
  it("extracts the DV certificate-policy OID from DER", () => {
    expect(readCertificatePolicyOids(certificateDer("dvPolicy"))).toEqual(["2.23.140.1.2.1"]);
  });

  it("returns empty when the certificatePolicies extension is absent", () => {
    expect(readCertificatePolicyOids(certificateDer("valid"))).toEqual([]);
  });

  it("throws DerParseError on malformed DER", () => {
    expect(() => readCertificatePolicyOids(new Uint8Array([0x30, 0x80]))).toThrow(DerParseError);
  });
});

describe("normalizeTlsCertificate — evidence", () => {
  it("records SANs, validity window, serial, and self-issued state for a valid leaf", () => {
    const result = normalize("valid");
    expect(result.leaf.subjectAltNames).toEqual(["example.com", "www.example.com"]);
    expect(result.leaf.notBefore).toBe("2020-01-01T00:00:00.000Z");
    expect(result.leaf.notAfter).toBe("2035-01-01T00:00:00.000Z");
    expect(result.leaf.serialNumber).toMatch(/^[0-9A-F]+$/);
    expect(result.leaf.assuranceLevel).toBe("unknown");
    expect(result.protocolVersion).toBe("TLSv1.3");
    expect(result.chainDepth).toBe(1);
  });

  it("classifies the DV policy OID as dv assurance", () => {
    const result = normalize("dvPolicy");
    expect(result.leaf.policyOids).toEqual(["2.23.140.1.2.1"]);
    expect(result.leaf.assuranceLevel).toBe("dv");
  });
});

describe("normalizeTlsCertificate — independent validation axes", () => {
  it("a trusted, current, matching certificate has no defects", () => {
    const result = normalize("valid");
    expect(result.validation).toMatchObject({
      chainTrusted: true,
      hostnameMatch: true,
      withinValidity: true,
      defects: [],
    });
  });

  it("distinguishes expired from a trust or hostname problem", () => {
    const result = normalize("expired", { chainTrusted: true, trustErrorCode: null });
    expect(result.validation.withinValidity).toBe(false);
    expect(result.validation.defects).toContain("expired");
    expect(result.validation.defects).not.toContain("untrusted");
    expect(result.validation.defects).not.toContain("hostname-mismatch");
  });

  it("distinguishes not-yet-valid", () => {
    const result = normalize("notYetValid", { chainTrusted: true, trustErrorCode: null });
    expect(result.validation.defects).toContain("not-yet-valid");
    expect(result.validation.defects).not.toContain("expired");
  });

  it("computes hostname mismatch independently of the trust signal", () => {
    // Trust asserted true, yet the SAN set does not cover the queried host.
    const result = normalize("hostnameMismatch", { chainTrusted: true, trustErrorCode: null });
    expect(result.validation.hostnameMatch).toBe(false);
    expect(result.validation.defects).toContain("hostname-mismatch");
    expect(result.validation.defects).not.toContain("untrusted");
  });

  it("reports both self-signed and untrusted for an untrusted self-issued leaf", () => {
    const result = normalize("selfSigned", {
      chainTrusted: false,
      trustErrorCode: "DEPTH_ZERO_SELF_SIGNED_CERT",
    });
    expect(result.leaf.selfIssued).toBe(true);
    expect(result.validation.defects).toEqual(
      expect.arrayContaining(["self-signed", "untrusted"]),
    );
  });

  it("matches a wildcard SAN against a subdomain via the standard identity checker", () => {
    const result = normalize("wildcard", {}, "api.example.com");
    expect(result.validation.hostnameMatch).toBe(true);
    expect(result.validation.defects).not.toContain("hostname-mismatch");
  });
});

describe("normalizeTlsCertificate — bounded analysis", () => {
  it("rejects an empty chain as malformed", () => {
    expect(() =>
      normalizeTlsCertificate(
        { ...handshake("valid"), certificateChain: [] },
        { hostname: "example.com", observedAt: OBSERVED_AT },
      ),
    ).toThrow(TlsCertificateAnalysisError);
  });

  it("rejects a chain deeper than the configured bound", () => {
    expect(() =>
      normalizeTlsCertificate(handshake("valid", { extraChain: ["valid", "valid"] }), {
        hostname: "example.com",
        observedAt: OBSERVED_AT,
        policy: { maxChainDepth: 2 },
      }),
    ).toThrow(new TlsCertificateAnalysisError("chain-too-deep"));
  });

  it("rejects a certificate larger than the configured bound", () => {
    expect(() =>
      normalizeTlsCertificate(handshake("valid"), {
        hostname: "example.com",
        observedAt: OBSERVED_AT,
        policy: { maxCertificateBytes: 16 },
      }),
    ).toThrow(new TlsCertificateAnalysisError("certificate-too-large"));
  });

  it("rejects malformed DER as a certificate-malformed analysis error", () => {
    expect(() =>
      normalizeTlsCertificate(
        { ...handshake("valid"), certificateChain: [new Uint8Array([1, 2, 3, 4])] },
        { hostname: "example.com", observedAt: OBSERVED_AT },
      ),
    ).toThrow(TlsCertificateAnalysisError);
  });
});
