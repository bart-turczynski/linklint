import { describe, expect, it } from "vitest";

import {
  createSafeTlsInspector,
  createSafeTransport,
  type TlsInspectionPolicy,
} from "../src/transport/index.js";
import {
  TransportFixtureHarness,
  type TransportFixtureScript,
} from "../src/testing/index.js";
import type { TlsHandshakeObservation } from "../src/transport/tls-types.js";
import { handshake } from "./fixtures/tls-certificates.js";

const PUBLIC_A = "93.184.216.34";
const URL = "https://example.com/login";

function inspector(script: TransportFixtureScript, policy?: Partial<TlsInspectionPolicy>) {
  const harness = new TransportFixtureHarness({ startTime: "2026-01-01T00:00:00.000Z", ...script });
  const inst = createSafeTlsInspector({
    resolver: harness.resolver,
    observer: harness.tlsObserver,
    clock: harness.clock,
    ...(policy === undefined ? {} : { policy }),
  });
  return { harness, inspect: inst };
}

function resolveExample(address = PUBLIC_A) {
  return [
    { hostname: "example.com", outcome: { value: [{ address, family: 4 as const, ttlSeconds: 60 }] } },
  ];
}

function observeStep(observation = handshake("valid"), address = PUBLIC_A) {
  return [
    {
      expect: { hostname: "example.com", address, port: 443, serverName: "example.com" },
      outcome: { value: observation },
    },
  ];
}

describe("createSafeTlsInspector — observed", () => {
  it("observes a valid certificate through the pinned transport and records evidence", async () => {
    const { harness, inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(),
    });

    const outcome = await inspect.inspect({ url: URL });

    expect(outcome.status).toBe("observed");
    if (outcome.status !== "observed") throw new Error("unreachable");
    expect(outcome.observation.validation.defects).toEqual([]);
    expect(outcome.observation.leaf.subjectAltNames).toContain("example.com");
    expect(outcome.evidence).toMatchObject({
      type: "tls.attempt",
      protocol: "https:",
      hostname: "example.com",
      port: 443,
      resolvedAddresses: [PUBLIC_A],
      selectedAddress: PUBLIC_A,
    });
    // Original-host SNI was preserved to the observer.
    expect(harness.tlsObserver.calls[0]).toMatchObject({ serverName: "example.com", address: PUBLIC_A });
    harness.assertExhausted();
  });

  it("still OBSERVES an expired certificate rather than failing", async () => {
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(handshake("expired", { chainTrusted: true, trustErrorCode: null })),
    });

    const outcome = await inspect.inspect({ url: URL });
    expect(outcome.status).toBe("observed");
    if (outcome.status !== "observed") throw new Error("unreachable");
    expect(outcome.observation.validation.defects).toContain("expired");
  });

  it("still OBSERVES an untrusted self-signed certificate", async () => {
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(
        handshake("selfSigned", { chainTrusted: false, trustErrorCode: "DEPTH_ZERO_SELF_SIGNED_CERT" }),
      ),
    });

    const outcome = await inspect.inspect({ url: URL });
    expect(outcome.status).toBe("observed");
    if (outcome.status !== "observed") throw new Error("unreachable");
    expect(outcome.observation.validation.defects).toEqual(
      expect.arrayContaining(["untrusted", "self-signed"]),
    );
  });
});

describe("createSafeTlsInspector — blocked is reserved for transport policy", () => {
  it("blocks a prohibited pinned address and never connects", async () => {
    const { harness, inspect } = inspector({
      resolver: resolveExample("10.0.0.5"),
      tlsObserver: [],
    });

    const outcome = await inspect.inspect({ url: URL });

    expect(outcome.status).toBe("blocked");
    if (outcome.status !== "blocked") throw new Error("unreachable");
    expect(outcome.cause).toMatchObject({ code: "prohibited-address", details: { address: "10.0.0.5" } });
    expect(harness.tlsObserver.calls).toEqual([]);
    harness.assertExhausted();
  });
});

describe("createSafeTlsInspector — incomplete causes", () => {
  it("reports dns-not-found as incomplete", async () => {
    const { inspect } = inspector({
      resolver: [{ hostname: "example.com", outcome: { value: [] } }],
      tlsObserver: [],
    });
    await expect(inspect.inspect({ url: URL })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "dns-not-found" },
    });
  });

  it("maps a handshake failure to incomplete tls-handshake without leaking messages", async () => {
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: [
        {
          expect: { hostname: "example.com", address: PUBLIC_A, port: 443, serverName: "example.com" },
          outcome: { failure: "tls-handshake" },
        },
      ],
    });
    const outcome = await inspect.inspect({ url: URL });
    expect(outcome).toMatchObject({ status: "incomplete", cause: { code: "tls-handshake" } });
    expect(JSON.stringify(outcome)).not.toContain("scripted fixture failure");
  });

  it("rejects a connected address that does not match the pinned address", async () => {
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(handshake("valid", { remoteAddress: "203.0.113.9" })),
    });
    await expect(inspect.inspect({ url: URL })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "connection-address-mismatch" },
    });
  });

  /**
   * LINK-abozdqtp — the observation's peer fields are compared against the pin,
   * so an observer that reports nothing must not report the pin back. Absent and
   * malformed peer evidence fails on the same footing as a wrong address.
   */
  it.each([
    ["an absent remote address", { remoteAddress: undefined }],
    ["an absent remote port", { remotePort: undefined }],
    ["a malformed remote address", { remoteAddress: "example.com" }],
    ["an out-of-range remote port", { remotePort: 65_536 }],
    ["a wrong remote port", { remotePort: 8443 }],
    // The pinned IPv4 literal written in mapped form. Refused: the boundary
    // compares within one family, and an unobserved equivalence is not a
    // confirmed one.
    ["an IPv4-mapped form of the pinned address", { remoteAddress: `::ffff:${PUBLIC_A}` }],
  ])("refuses %s as connection-address-mismatch", async (_label, override) => {
    const observation = {
      ...handshake("valid"),
      ...override,
    } as unknown as TlsHandshakeObservation;
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(observation),
    });
    await expect(inspect.inspect({ url: URL })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "connection-address-mismatch" },
    });
  });

  it("observes normally when the reported peer matches the pinned address and port", async () => {
    const { inspect } = inspector({
      resolver: resolveExample(),
      tlsObserver: observeStep(handshake("valid", { remoteAddress: PUBLIC_A, remotePort: 443 })),
    });
    await expect(inspect.inspect({ url: URL })).resolves.toMatchObject({ status: "observed" });
  });

  it("treats certificate-analysis limits as incomplete, never blocked", async () => {
    const { inspect } = inspector(
      { resolver: resolveExample(), tlsObserver: observeStep() },
      { maxCertificateBytes: 16 },
    );
    await expect(inspect.inspect({ url: URL })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "certificate-too-large" },
    });
  });

  it("rejects a non-https URL as incomplete unsupported-scheme without resolving", async () => {
    const { harness, inspect } = inspector({ resolver: [], tlsObserver: [] });
    await expect(inspect.inspect({ url: "http://example.com/" })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "unsupported-scheme" },
    });
    expect(harness.resolver.calls).toEqual([]);
    harness.assertExhausted();
  });

  it("rejects URL credentials as incomplete", async () => {
    const { inspect } = inspector({ resolver: [], tlsObserver: [] });
    await expect(
      inspect.inspect({ url: "https://user:pass@example.com/" }),
    ).resolves.toMatchObject({ status: "incomplete", cause: { code: "url-credentials" } });
  });

  it("returns caller-aborted when the signal is already aborted", async () => {
    const { harness, inspect } = inspector({ resolver: [], tlsObserver: [] });
    const controller = new AbortController();
    controller.abort();
    await expect(
      inspect.inspect({ url: URL, signal: controller.signal }),
    ).resolves.toMatchObject({ status: "incomplete", cause: { code: "caller-aborted" } });
    expect(harness.resolver.calls).toEqual([]);
  });

  it("enforces the total inspection deadline with the deterministic clock", async () => {
    const { harness, inspect } = inspector(
      {
        resolver: [
          {
            hostname: "example.com",
            delayMs: 101,
            outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 60 }] },
          },
        ],
        tlsObserver: [],
      },
      { maxTotalTimeMs: 100 },
    );
    const pending = inspect.inspect({ url: URL });
    harness.clock.advanceBy(100);
    await expect(pending).resolves.toMatchObject({ status: "incomplete", cause: { code: "timeout" } });
    expect(harness.tlsObserver.calls).toEqual([]);
  });
});

describe("observe mode cannot weaken or leak into the fetch path", () => {
  it("blocks the same prohibited address on both fetch and observe, and observe never sends HTTP", async () => {
    const script: TransportFixtureScript = {
      startTime: "2026-01-01T00:00:00.000Z",
      resolver: resolveExample("127.0.0.1"),
      tlsObserver: [],
    };
    const observeHarness = new TransportFixtureHarness(script);
    const observe = createSafeTlsInspector({
      resolver: observeHarness.resolver,
      observer: observeHarness.tlsObserver,
      clock: observeHarness.clock,
    });
    const observeOutcome = await observe.inspect({ url: URL });
    expect(observeOutcome.status).toBe("blocked");
    // The observe path has no HTTP port at all: nothing can be fetched through it.
    expect(observeHarness.http.calls).toEqual([]);

    const fetchHarness = new TransportFixtureHarness(script);
    const fetchTransport = createSafeTransport({
      resolver: fetchHarness.resolver,
      connector: fetchHarness.connector,
      http: fetchHarness.http,
      clock: fetchHarness.clock,
    });
    const fetchOutcome = await fetchTransport
      .createSession()
      .fetch({ url: URL, authorization: { kind: "destination-fetch", url: URL } });
    expect(fetchOutcome).toMatchObject({ status: "blocked", cause: { code: "prohibited-address" } });
  });

  it("performs no HTTP request on a successful observation", async () => {
    const { harness, inspect } = inspector({ resolver: resolveExample(), tlsObserver: observeStep() });
    await inspect.inspect({ url: URL });
    expect(harness.http.calls).toEqual([]);
    expect(harness.connector.calls).toEqual([]);
  });
});
