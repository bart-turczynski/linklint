import { gunzipSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  FixtureAbortError,
  FixtureClock,
  FixtureFailure,
  TransportFixtureHarness,
  UnexpectedFixtureCall,
  type FixtureConnection,
  type HttpResponse,
} from "../src/testing/index.js";

const PUBLIC_ADDRESS_A = "93.184.216.34";
const PUBLIC_ADDRESS_B = "93.184.216.35";

function connection(
  id: string,
  remoteAddress = PUBLIC_ADDRESS_A,
): FixtureConnection {
  return {
    id,
    protocol: "https:",
    remoteAddress,
    remotePort: 443,
    tls: {
      authorized: true,
      serverName: "origin.example",
      peerDnsNames: ["origin.example"],
    },
  };
}

async function readBody(response: HttpResponse): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of response.body) chunks.push(chunk);
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return joined;
}

describe("deterministic transport fixture clock", () => {
  it("advances sleeps without wall time and settles equal deadlines in script order", async () => {
    const clock = new FixtureClock("2026-07-17T10:00:00.000Z");
    const settled: string[] = [];
    const first = clock.sleep(250).then(() => settled.push("first"));
    const second = clock.sleep(250).then(() => settled.push("second"));

    clock.advanceBy(249);
    await Promise.resolve();
    expect(settled).toEqual([]);
    expect(clock.now().toISOString()).toBe("2026-07-17T10:00:00.249Z");

    clock.advanceBy(1);
    await Promise.all([first, second]);
    expect(settled).toEqual(["first", "second"]);
    expect(clock.pendingSleepCount).toBe(0);
  });

  it("uses a stable abort error and removes cancelled sleeps", async () => {
    const clock = new FixtureClock();
    const controller = new AbortController();
    const pending = clock.sleep(100, controller.signal);
    controller.abort();

    await expect(pending).rejects.toBeInstanceOf(FixtureAbortError);
    expect(clock.pendingSleepCount).toBe(0);
  });
});

describe("resolver and pinned connection fixtures", () => {
  it("scripts DNS address changes in exact call order", async () => {
    const harness = new TransportFixtureHarness({
      resolver: [
        {
          hostname: "origin.example",
          outcome: {
            value: [{ address: PUBLIC_ADDRESS_A, family: 4, ttlSeconds: 30 }],
          },
        },
        {
          hostname: "origin.example",
          outcome: {
            value: [{ address: PUBLIC_ADDRESS_B, family: 4, ttlSeconds: 30 }],
          },
        },
      ],
    });

    expect(await harness.resolver.resolve({ hostname: "origin.example" })).toEqual([
      { address: PUBLIC_ADDRESS_A, family: 4, ttlSeconds: 30 },
    ]);
    expect(await harness.resolver.resolve({ hostname: "origin.example" })).toEqual([
      { address: PUBLIC_ADDRESS_B, family: 4, ttlSeconds: 30 },
    ]);
    expect(harness.resolver.calls.map((call) => call.hostname)).toEqual([
      "origin.example",
      "origin.example",
    ]);
    harness.assertExhausted();
  });

  it("separately asserts the selected address and original hostname/SNI identity", async () => {
    const expectedConnection = connection("connection-1");
    const harness = new TransportFixtureHarness({
      connector: [
        {
          expect: {
            protocol: "https:",
            hostname: "origin.example",
            address: PUBLIC_ADDRESS_A,
            port: 443,
            serverName: "origin.example",
          },
          outcome: { value: expectedConnection },
        },
      ],
    });

    await expect(
      harness.connector.connect({
        protocol: "https:",
        hostname: "origin.example",
        address: PUBLIC_ADDRESS_A,
        port: 443,
        serverName: "origin.example",
      }),
    ).resolves.toEqual(expectedConnection);
    harness.assertExhausted();
  });

  it("fails closed when a connector tries a re-resolved address instead of the pinned one", async () => {
    const harness = new TransportFixtureHarness({
      connector: [
        {
          expect: {
            protocol: "https:",
            hostname: "origin.example",
            address: PUBLIC_ADDRESS_A,
            port: 443,
            serverName: "origin.example",
          },
          outcome: { value: connection("unused") },
        },
      ],
    });

    await expect(
      harness.connector.connect({
        protocol: "https:",
        hostname: "origin.example",
        address: PUBLIC_ADDRESS_B,
        port: 443,
        serverName: "origin.example",
      }),
    ).rejects.toMatchObject({
      name: "UnexpectedFixtureCall",
      port: "connector",
    });
  });

  it("supports proving a prohibited DNS answer is blocked before connection", async () => {
    const harness = new TransportFixtureHarness({
      resolver: [
        {
          hostname: "internal.example",
          outcome: {
            value: [{ address: "169.254.169.254", family: 4, ttlSeconds: 1 }],
          },
        },
      ],
    });

    const answers = await harness.resolver.resolve({ hostname: "internal.example" });
    expect(answers[0]?.address).toBe("169.254.169.254");
    // L0 will classify the answer and stop here. An accidental connection is an
    // unscripted call and therefore fails instead of reaching a real socket.
    expect(harness.connector.calls).toEqual([]);
    harness.assertExhausted();
  });
});

describe("HTTP protocol and budget fixtures", () => {
  it("represents redirects, relative Location, HTTP Refresh, and HTML meta refresh", async () => {
    const harness = new TransportFixtureHarness({
      http: [
        {
          expect: { connectionId: "c1", url: "https://origin.example/a", method: "GET" },
          outcome: {
            value: { status: 302, headers: { Location: "../landing" } },
          },
        },
        {
          expect: { connectionId: "c2", url: "https://origin.example/landing", method: "GET" },
          outcome: {
            value: { status: 200, headers: { Refresh: "0; url=/header-target" } },
          },
        },
        {
          expect: { connectionId: "c3", url: "https://origin.example/header-target", method: "GET" },
          outcome: {
            value: {
              status: 200,
              headers: { "Content-Type": "text/html; charset=utf-8" },
              body: '<meta http-equiv="refresh" content="1; url=./final">',
            },
          },
        },
      ],
    });

    const redirect = await harness.http.request({
      connectionId: "c1",
      url: "https://origin.example/a",
      method: "GET",
    });
    const refresh = await harness.http.request({
      connectionId: "c2",
      url: "https://origin.example/landing",
      method: "GET",
    });
    const meta = await harness.http.request({
      connectionId: "c3",
      url: "https://origin.example/header-target",
      method: "GET",
    });

    expect(redirect.headers.location).toEqual(["../landing"]);
    expect(refresh.headers.refresh).toEqual(["0; url=/header-target"]);
    expect(new TextDecoder().decode(await readBody(meta))).toContain("url=./final");
    harness.assertExhausted();
  });

  it("asserts stripped credentials and other forbidden destination headers", async () => {
    const harness = new TransportFixtureHarness({
      http: [
        {
          expect: {
            connectionId: "c1",
            url: "https://destination.example/",
            method: "HEAD",
            headers: { Host: "destination.example" },
            absentHeaders: ["authorization", "cookie", "referer"],
          },
          outcome: { value: { status: 204 } },
        },
      ],
    });

    await expect(
      harness.http.request({
        connectionId: "c1",
        url: "https://destination.example/",
        method: "HEAD",
        headers: { host: "destination.example" },
      }),
    ).resolves.toMatchObject({ status: 204 });
    harness.assertExhausted();
  });

  it("streams chunks so callers can stop exactly at an encoded-byte budget", async () => {
    const harness = new TransportFixtureHarness({
      http: [
        {
          expect: { connectionId: "c1", url: "https://origin.example/body", method: "GET" },
          outcome: {
            value: {
              status: 200,
              body: [{ bytes: "1234" }, { bytes: "5678" }, { bytes: "must-not-be-read" }],
            },
          },
        },
      ],
    });
    const response = await harness.http.request({
      connectionId: "c1",
      url: "https://origin.example/body",
      method: "GET",
    });

    let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > 6) break;
    }
    expect(bytes).toBe(8);
    expect(harness.http.bodies[0]).toMatchObject({ chunksRead: 2, bytesRead: 8 });
  });

  it("carries real compressed bytes for deterministic decompression limits and failures", async () => {
    const decoded = new TextEncoder().encode("x".repeat(4_096));
    const encoded = gzipSync(decoded);
    const harness = new TransportFixtureHarness({
      http: [
        {
          expect: { connectionId: "c1", url: "https://origin.example/gzip", method: "GET" },
          outcome: {
            value: {
              status: 200,
              headers: { "Content-Encoding": "gzip" },
              body: encoded,
            },
          },
        },
      ],
    });
    const response = await harness.http.request({
      connectionId: "c1",
      url: "https://origin.example/gzip",
      method: "GET",
    });
    const wire = await readBody(response);

    expect(response.headers["content-encoding"]).toEqual(["gzip"]);
    expect(wire.byteLength).toBeLessThan(decoded.byteLength);
    expect(gunzipSync(wire).byteLength).toBeGreaterThan(1_024);
  });

  it("drives response and body delays from the shared clock for total-time budgets", async () => {
    const harness = new TransportFixtureHarness({
      http: [
        {
          expect: { connectionId: "c1", url: "https://origin.example/slow", method: "GET" },
          delayMs: 50,
          outcome: {
            value: { status: 200, body: [{ bytes: "one", delayMs: 75 }] },
          },
        },
      ],
    });

    const responsePending = harness.http.request({
      connectionId: "c1",
      url: "https://origin.example/slow",
      method: "GET",
    });
    harness.clock.advanceBy(50);
    const response = await responsePending;
    const next = response.body[Symbol.asyncIterator]().next();
    harness.clock.advanceBy(75);
    await expect(next).resolves.toMatchObject({ done: false });
    expect(harness.clock.now().toISOString()).toBe("2026-01-01T00:00:00.125Z");
  });
});

describe("operational incomplete paths", () => {
  it("emits stable DNS, TLS, HTTP, and decompression failure codes", async () => {
    const dns = new TransportFixtureHarness({
      resolver: [
        {
          hostname: "missing.example",
          outcome: { failure: "dns-not-found" },
        },
      ],
    });
    await expect(dns.resolver.resolve({ hostname: "missing.example" })).rejects.toMatchObject({
      code: "dns-not-found",
    });

    const tls = new TransportFixtureHarness({
      connector: [
        {
          expect: {
            protocol: "https:",
            hostname: "origin.example",
            address: PUBLIC_ADDRESS_A,
            port: 443,
            serverName: "origin.example",
          },
          outcome: { failure: "tls-certificate" },
        },
      ],
    });
    await expect(
      tls.connector.connect({
        protocol: "https:",
        hostname: "origin.example",
        address: PUBLIC_ADDRESS_A,
        port: 443,
        serverName: "origin.example",
      }),
    ).rejects.toMatchObject({ code: "tls-certificate" });

    for (const failure of ["http-malformed", "decompression-error"] as const) {
      const http = new TransportFixtureHarness({
        http: [
          {
            expect: { connectionId: "c1", url: "https://origin.example/", method: "GET" },
            outcome: { failure },
          },
        ],
      });
      await expect(
        http.http.request({
          connectionId: "c1",
          url: "https://origin.example/",
          method: "GET",
        }),
      ).rejects.toMatchObject({ code: failure });
    }
  });

  it("distinguishes scripted operational failures from unexpected fixture calls", async () => {
    const harness = new TransportFixtureHarness();
    const failure = harness.resolver.resolve({ hostname: "unscripted.example" });

    await expect(failure).rejects.toBeInstanceOf(UnexpectedFixtureCall);
    await expect(failure).rejects.not.toBeInstanceOf(FixtureFailure);
  });
});
