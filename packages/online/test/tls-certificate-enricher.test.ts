import { describe, expect, it } from "vitest";
import type { EnrichmentReport, InspectResult } from "linklint";

import { createSafeTlsInspector, type SafeTlsInspector } from "../src/transport/index.js";
import {
  createTlsCertificateEnricher,
  TLS_SOURCE_DESCRIPTOR,
  TLS_SOURCE_ID,
} from "../src/reputation/index.js";
import { TransportFixtureHarness, type TransportFixtureScript } from "../src/testing/index.js";
import { handshake } from "./fixtures/tls-certificates.js";
import { assertOnlineSourceContract } from "./contract/online-source-contract-kit.js";

const NOW = new Date("2026-01-01T00:00:00.000Z");
const PUBLIC_A = "93.184.216.34";

function fakeResult(opts: {
  input: string;
  scheme: string | null;
  effectiveHost: string | null;
  port?: number | null;
}): InspectResult {
  return {
    input: opts.input,
    parsed:
      opts.scheme === null && opts.effectiveHost === null
        ? null
        : { scheme: opts.scheme, effectiveHost: opts.effectiveHost, port: opts.port ?? null },
    reasons: [],
  } as unknown as InspectResult;
}

function inspectorFor(script: TransportFixtureScript): SafeTlsInspector {
  const harness = new TransportFixtureHarness({ startTime: "2026-01-01T00:00:00.000Z", ...script });
  return createSafeTlsInspector({
    resolver: harness.resolver,
    observer: harness.tlsObserver,
    clock: harness.clock,
  });
}

function resolveExample(address = PUBLIC_A) {
  return [
    { hostname: "example.com", outcome: { value: [{ address, family: 4 as const, ttlSeconds: 60 }] } },
  ];
}

function observeStep(observation = handshake("valid")) {
  return [
    {
      expect: { hostname: "example.com", address: PUBLIC_A, port: 443, serverName: "example.com" },
      outcome: { value: observation },
    },
  ];
}

async function run(inspector: SafeTlsInspector, result: InspectResult): Promise<EnrichmentReport> {
  const enricher = createTlsCertificateEnricher({ terms: { commercialMode: "commercial" }, inspector, now: () => NOW });
  return (await enricher.enrich(result, { previousOutcomes: [] })) as EnrichmentReport;
}

const HTTPS_INPUT = fakeResult({
  input: "https://example.com/login",
  scheme: "https",
  effectiveHost: "example.com",
});

describe("TLS_SOURCE_DESCRIPTOR", () => {
  it("satisfies the shared online-source contract", () => {
    assertOnlineSourceContract(TLS_SOURCE_DESCRIPTOR);
  });

  it("is a live-provider, evidence-only, no-credential source disclosing only host", () => {
    expect(TLS_SOURCE_DESCRIPTOR.dataOrigin).toEqual({
      kind: "live-provider",
      recipient: "tls.inspected-origin",
    });
    expect(TLS_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["host"]);
    expect(TLS_SOURCE_DESCRIPTOR.disclosure.consentRequired).toEqual([]);
    expect(TLS_SOURCE_DESCRIPTOR.credentials).toEqual({ kind: "none" });
    expect(TLS_SOURCE_DESCRIPTOR.scoring).toBe("evidence-only");
    expect(TLS_SOURCE_DESCRIPTOR.evidenceScope).toEqual(["tls.certificate"]);
  });
});

describe("createTlsCertificateEnricher — evidence", () => {
  it("emits tls.certificate evidence and never a finding for a valid certificate", async () => {
    const inspector = inspectorFor({ resolver: resolveExample(), tlsObserver: observeStep() });
    const report = await run(inspector, HTTPS_INPUT);

    expect(report.outcomes).toHaveLength(1);
    const outcome = report.outcomes[0]!;
    expect(outcome).toMatchObject({
      sourceId: TLS_SOURCE_ID,
      status: "success",
      subject: { kind: "host", value: "example.com" },
      findings: [],
    });
    expect(outcome.evidence).toHaveLength(1);
    expect(outcome.evidence[0]).toMatchObject({
      type: "tls.certificate",
      subject: { kind: "host", value: "example.com" },
      provenance: { kind: "declared", source: { name: TLS_SOURCE_ID } },
    });
    expect(outcome.evidence[0]!.payload).toMatchObject({
      subjectAltNames: ["example.com", "www.example.com"],
      notBefore: "2020-01-01T00:00:00.000Z",
      notAfter: "2035-01-01T00:00:00.000Z",
      chainTrusted: true,
      hostnameMatch: true,
      withinValidity: true,
      defects: [],
    });
    // Live observation declares no expiry.
    expect(outcome.freshness).toEqual({ status: "unknown", expiresAt: null });
  });

  it("records DV assurance and policy OIDs in evidence", async () => {
    const inspector = inspectorFor({
      resolver: resolveExample(),
      tlsObserver: observeStep(handshake("dvPolicy")),
    });
    const report = await run(inspector, HTTPS_INPUT);
    expect(report.outcomes[0]!.evidence[0]!.payload).toMatchObject({
      assuranceLevel: "dv",
      policyOids: ["2.23.140.1.2.1"],
    });
  });

  it("still records evidence (no finding) when the certificate has defects", async () => {
    const inspector = inspectorFor({
      resolver: resolveExample(),
      tlsObserver: observeStep(
        handshake("selfSigned", { chainTrusted: false, trustErrorCode: "DEPTH_ZERO_SELF_SIGNED_CERT" }),
      ),
    });
    const report = await run(inspector, HTTPS_INPUT);
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.findings).toEqual([]);
    expect(outcome.evidence[0]!.payload.defects).toEqual(
      expect.arrayContaining(["self-signed", "untrusted"]),
    );
  });
});

describe("createTlsCertificateEnricher — degraded outcomes are never safety claims", () => {
  it("skips non-HTTPS input without attempting a connection", async () => {
    let inspected = false;
    const inspector: SafeTlsInspector = {
      inspect: async () => {
        inspected = true;
        throw new Error("must not inspect");
      },
    };
    const report = await run(
      inspector,
      fakeResult({ input: "http://example.com/", scheme: "http", effectiveHost: "example.com" }),
    );
    expect(report.outcomes[0]).toMatchObject({
      status: "skipped",
      cause: { code: "tls-not-https-endpoint", retryable: false },
    });
    expect(inspected).toBe(false);
  });

  it("skips a prohibited destination (transport-policy block)", async () => {
    const inspector = inspectorFor({ resolver: resolveExample("10.0.0.5"), tlsObserver: [] });
    const report = await run(inspector, HTTPS_INPUT);
    expect(report.outcomes[0]).toMatchObject({
      status: "skipped",
      cause: { code: "tls-prohibited-address", retryable: false },
    });
    expect(report.outcomes[0]!.findings).toEqual([]);
  });

  it("fails on a handshake error and retries are allowed", async () => {
    const inspector = inspectorFor({
      resolver: resolveExample(),
      tlsObserver: [
        {
          expect: { hostname: "example.com", address: PUBLIC_A, port: 443, serverName: "example.com" },
          outcome: { failure: "tls-handshake" },
        },
      ],
    });
    const report = await run(inspector, HTTPS_INPUT);
    expect(report.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "tls-tls-handshake", retryable: true },
    });
  });

  it("fails non-retryably on a malformed certificate", async () => {
    const inspector = inspectorFor({
      resolver: resolveExample(),
      tlsObserver: observeStep({
        ...handshake("valid"),
        certificateChain: [new Uint8Array([1, 2, 3, 4])],
      }),
    });
    const report = await run(inspector, HTTPS_INPUT);
    expect(report.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "tls-certificate-malformed", retryable: false },
    });
  });
});
