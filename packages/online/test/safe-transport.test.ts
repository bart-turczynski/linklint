import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  classifyTransportAddress,
  createSafeTransport,
  DEFAULT_TRANSPORT_POLICY,
  resolveTransportPolicy,
  SystemClock,
  type DestinationFetchAuthorization,
  type SafeFetchRequest,
} from "../src/transport/index.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../src/testing/index.js";

const PUBLIC_A = "93.184.216.34";
const PUBLIC_B = "93.184.216.35";
const URL_A = "https://origin.example/start";

function authorization(url: string): DestinationFetchAuthorization {
  return { kind: "destination-fetch", url };
}

function connection(
  id: string,
  address = PUBLIC_A,
  hostname = "origin.example",
  port = 443,
): FixtureConnection {
  return {
    id,
    protocol: "https:",
    remoteAddress: address,
    remotePort: port,
    tls: {
      authorized: true,
      serverName: hostname,
      peerDnsNames: [hostname],
    },
  };
}

function session(
  script: TransportFixtureScript,
  policy: Parameters<typeof createSafeTransport>[0]["policy"] = undefined,
) {
  const harness = new TransportFixtureHarness(script);
  const transport = createSafeTransport({
    resolver: harness.resolver,
    connector: harness.connector,
    http: harness.http,
    clock: harness.clock,
    ...(policy === undefined ? {} : { policy }),
  });
  return { harness, session: transport.createSession() };
}

function publicSuccessScript(
  url = URL_A,
  body = "ok",
): TransportFixtureScript {
  return {
    startTime: "2026-07-17T12:00:00.000Z",
    resolver: [
      {
        hostname: "origin.example",
        outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 60 }] },
      },
    ],
    connector: [
      {
        expect: {
          protocol: "https:",
          hostname: "origin.example",
          address: PUBLIC_A,
          port: 443,
          serverName: "origin.example",
        },
        outcome: { value: connection("c1") },
      },
    ],
    http: [
      {
        expect: { connectionId: "c1", url, method: "GET" },
        outcome: { value: { status: 200, body } },
      },
    ],
  };
}

describe("safe destination address policy", () => {
  it.each([
    ["127.0.0.1", "ip_loopback"],
    ["10.0.0.1", "ip_private"],
    ["169.254.169.254", "ip_cloud_metadata"],
    ["192.0.2.1", "documentation"],
    // S3 (LINK-qvsrmrzv): core's ranges now come from the IANA special-purpose
    // registries, where 198.18.0.0/15 (Benchmarking) is Globally Reachable =
    // False — so core classifies it `ip_reserved` and the answer arrives BEFORE
    // this package's supplemental "benchmark" rule. The address is blocked
    // either way; only the label moved. The documentation rows below still fall
    // through to the supplemental table, because core deliberately leaves
    // documentation prefixes unclassified (inert, not an SSRF target).
    ["198.18.0.1", "ip_reserved"],
    ["2001:db8::1", "documentation"],
    // Core is consulted before the supplemental table, and it now unwraps the
    // IPv4 in the low 32 bits of the transition wrappers. `::ffff:7f00:1` really
    // is 127.0.0.1, so the precise bucket wins over the blanket ::ffff:0:0/96
    // "reserved" rule. `::808:808` unwraps to public 8.8.8.8, which core leaves
    // unclassified, so it still falls through to the supplemental rule.
    ["::808:808", "transition"],
    ["::ffff:7f00:1", "ip_loopback"],
  ])("blocks %s as %s", (address, category) => {
    expect(classifyTransportAddress(address)).toMatchObject({
      allowed: false,
      category,
    });
  });

  it.each([PUBLIC_A, "2606:4700:4700::1111"])("allows global address %s", (address) => {
    expect(classifyTransportAddress(address)).toMatchObject({
      allowed: true,
      category: null,
    });
  });

  it("rejects invalid addresses and mandatory unbounded policies", () => {
    expect(classifyTransportAddress("not-an-address")).toMatchObject({
      allowed: false,
      category: "invalid",
    });
    expect(() => resolveTransportPolicy({ maxHops: 0 })).toThrow(RangeError);
    expect(() => resolveTransportPolicy({ maxTotalTimeMs: Number.POSITIVE_INFINITY })).toThrow(
      RangeError,
    );
    expect(resolveTransportPolicy(undefined)).toEqual(DEFAULT_TRANSPORT_POLICY);
  });
});

describe("safe HTTP(S) authorization and DNS pinning", () => {
  it("pins a public answer, preserves Host/SNI, strips credentials, and records evidence", async () => {
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      http: [{
        expect: {
          connectionId: "c1",
          url: URL_A,
          method: "GET",
          headers: {
            host: "origin.example",
            "user-agent": "linklint-test",
            "accept-encoding": "gzip, deflate, br",
          },
          absentHeaders: [
            "authorization",
            "proxy-authorization",
            "cookie",
            "referer",
            "x-api-key",
          ],
        },
        outcome: { value: { status: 200, body: "ok" } },
      }],
    };
    const { harness, session: transportSession } = session(script);

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
      headers: {
        "User-Agent": "linklint-test",
        Authorization: "Bearer secret",
        "Proxy-Authorization": "Basic secret",
        Cookie: "session=secret",
        Referer: "https://private.example/path",
        "X-Api-Key": "secret",
      },
    });

    expect(outcome).toMatchObject({
      status: "success",
      subject: { kind: "url", value: URL_A },
      observedAt: "2026-07-17T12:00:00.000Z",
      evidence: {
        type: "transport.attempt",
        hop: 1,
        hostname: "origin.example",
        resolvedAddresses: [PUBLIC_A],
        selectedAddress: PUBLIC_A,
      },
      response: { status: 200, encodedBytes: 2, decompressedBytes: 2 },
    });
    if (outcome.status === "success") {
      expect(new TextDecoder().decode(outcome.response.body)).toBe("ok");
    }
    expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    expect(transportSession.usage).toMatchObject({
      hops: 1,
      encodedBytes: 2,
      decompressedBytes: 2,
    });
    harness.assertExhausted();
  });

  it("sends a validated same-origin Referer through the dedicated channel only", async () => {
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      http: [{
        expect: {
          connectionId: "c1",
          url: URL_A,
          method: "GET",
          headers: { referer: "https://origin.example/from?a=1" },
        },
        outcome: { value: { status: 200, body: "ok" } },
      }],
    };
    const { harness, session: transportSession } = session(script);

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
      // The header allowlist is NOT opened: a caller-supplied Referer is still
      // stripped, and the fragment never rides along on the synthetic one.
      headers: { Referer: "https://private.example/secret" },
      sameOriginReferer: "https://origin.example/from?a=1#section",
    });

    expect(outcome.status).toBe("success");
    expect(harness.http.calls[0]?.headers.referer).toBe("https://origin.example/from?a=1");
    harness.assertExhausted();
  });

  it.each([
    ["cross-origin host", "https://other.example/"],
    ["scheme-mismatched", "http://origin.example/"],
    ["port-mismatched", "https://origin.example:8443/"],
    ["relative", "/dashboard"],
    ["userinfo-bearing", "https://user:secret@origin.example/"],
    ["non-HTTP", "javascript:alert(1)"],
    ["unparsable", "https://"],
  ])("hard-blocks a %s Referer before any DNS or connection", async (_case, referer) => {
    const { harness, session: transportSession } = session({});

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
      sameOriginReferer: referer,
    });

    expect(outcome).toMatchObject({
      status: "blocked",
      cause: { code: "referer-not-same-origin" },
    });
    expect(harness.resolver.calls).toEqual([]);
    expect(harness.connector.calls).toEqual([]);
    expect(harness.http.calls).toEqual([]);
  });

  it("hard-blocks if any DNS answer is prohibited before selecting or connecting", async () => {
    const { harness, session: transportSession } = session({
      resolver: [
        {
          hostname: "origin.example",
          outcome: {
            value: [
              { address: PUBLIC_A, family: 4, ttlSeconds: 60 },
              { address: "169.254.169.254", family: 4, ttlSeconds: 1 },
            ],
          },
        },
      ],
    });

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome).toMatchObject({
      status: "blocked",
      cause: {
        code: "prohibited-address",
        details: { address: "169.254.169.254", category: "ip_cloud_metadata" },
      },
    });
    expect(harness.connector.calls).toEqual([]);
    expect(harness.http.calls).toEqual([]);
    harness.assertExhausted();
  });

  it("canonicalizes and classifies a literal address without a second DNS lookup", async () => {
    const rawUrl = "http://2130706433/admin";
    const { harness, session: transportSession } = session({});
    const outcome = await transportSession.fetch({
      url: rawUrl,
      authorization: authorization(rawUrl),
    });

    expect(outcome).toMatchObject({
      status: "blocked",
      subject: { value: "http://127.0.0.1/admin" },
      cause: {
        code: "prohibited-address",
        details: { address: "127.0.0.1", category: "ip_loopback" },
      },
    });
    expect(harness.resolver.calls).toEqual([]);
    expect(harness.connector.calls).toEqual([]);
  });

  it.each([
    {
      request: { url: URL_A, authorization: authorization("https://other.example/") },
      code: "authorization-required",
    },
    {
      request: {
        url: "ftp://origin.example/file",
        authorization: authorization("ftp://origin.example/file"),
      },
      code: "unsupported-scheme",
    },
    {
      request: {
        url: "https://user:secret@origin.example/",
        authorization: authorization("https://user:secret@origin.example/"),
      },
      code: "url-credentials",
    },
    {
      request: { url: "not a url", authorization: authorization("not a url") },
      code: "invalid-url",
    },
    {
      request: {
        url: URL_A,
        authorization: authorization(URL_A),
        method: "POST",
      } as unknown as SafeFetchRequest,
      code: "unsupported-method",
    },
  ] satisfies Array<{ request: SafeFetchRequest; code: string }>) (
    "blocks $code without touching a transport port",
    async ({ request, code }) => {
      const { harness, session: transportSession } = session({});
      const outcome = await transportSession.fetch(request);
      expect(outcome).toMatchObject({ status: "blocked", cause: { code } });
      expect(harness.resolver.calls).toEqual([]);
      expect(harness.connector.calls).toEqual([]);
      expect(harness.http.calls).toEqual([]);
    },
  );

  it("returns redirects manually and requires a separately authorized, re-resolved next hop", async () => {
    const redirected = "https://origin.example/landing";
    const { harness, session: transportSession } = session({
      resolver: [
        {
          hostname: "origin.example",
          outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
        },
        {
          hostname: "origin.example",
          outcome: { value: [{ address: PUBLIC_B, family: 4, ttlSeconds: 1 }] },
        },
      ],
      connector: [
        {
          expect: {
            protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
            port: 443, serverName: "origin.example",
          },
          outcome: { value: connection("c1", PUBLIC_A) },
        },
        {
          expect: {
            protocol: "https:", hostname: "origin.example", address: PUBLIC_B,
            port: 443, serverName: "origin.example",
          },
          outcome: { value: connection("c2", PUBLIC_B) },
        },
      ],
      http: [
        {
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 302, headers: { Location: "/landing" } } },
        },
        {
          expect: { connectionId: "c2", url: redirected, method: "GET" },
          outcome: { value: { status: 200, body: "done" } },
        },
      ],
    });

    const first = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    expect(first).toMatchObject({
      status: "success",
      response: { status: 302, headers: { location: ["/landing"] } },
    });
    expect(harness.resolver.calls).toHaveLength(1);

    const second = await transportSession.fetch({
      url: redirected,
      authorization: authorization(redirected),
    });
    expect(second).toMatchObject({
      status: "success",
      evidence: { hop: 2, selectedAddress: PUBLIC_B },
      response: { status: 200 },
    });
    expect(harness.resolver.calls).toHaveLength(2);
    expect(harness.connector.closedConnectionIds).toEqual(["c1", "c2"]);
    harness.assertExhausted();
  });

  it("rejects a mismatched remote address and an unverified TLS identity", async () => {
    for (const tlsFailure of [false, true]) {
      const baseConnection = connection("c1", tlsFailure ? PUBLIC_A : PUBLIC_B);
      const badConnection: FixtureConnection = tlsFailure
        ? { ...baseConnection, tls: { ...baseConnection.tls!, authorized: false } }
        : baseConnection;
      const script: TransportFixtureScript = {
        ...publicSuccessScript(),
        connector: [{
          expect: {
            protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
            port: 443, serverName: "origin.example",
          },
          outcome: { value: badConnection },
        }],
        http: [],
      };
      const { harness, session: transportSession } = session(script);
      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });
      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: { code: tlsFailure ? "tls-certificate" : "connection-address-mismatch" },
      });
      expect(harness.http.calls).toEqual([]);
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
      harness.assertExhausted();
    }
  });

  /**
   * LINK-abozdqtp — the address check compares the connection's reported peer
   * against the pin, so a connector that cannot observe the peer must fail
   * rather than report the requested values back. Absent and malformed peer
   * evidence is refused on exactly the same footing as a wrong address.
   */
  it.each([
    ["an absent remote address", { remoteAddress: undefined }],
    ["an absent remote port", { remotePort: undefined }],
    ["a malformed remote address", { remoteAddress: "origin.example" }],
    ["an out-of-range remote port", { remotePort: 65_536 }],
    ["a wrong remote port", { remotePort: 8443 }],
    // `::ffff:93.184.216.34` is the same host as the pinned IPv4 literal written
    // in mapped form. It is refused: the boundary compares within one family,
    // and an unobserved-equivalence is not a confirmed one.
    ["an IPv4-mapped form of the pinned address", { remoteAddress: "::ffff:93.184.216.34" }],
  ])("refuses %s as connection-address-mismatch", async (_label, override) => {
    const badConnection = { ...connection("c1"), ...override } as unknown as FixtureConnection;
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      connector: [{
        expect: {
          protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
          port: 443, serverName: "origin.example",
        },
        outcome: { value: badConnection },
      }],
      http: [],
    };
    const { harness, session: transportSession } = session(script);

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome).toMatchObject({
      status: "incomplete",
      cause: { code: "connection-address-mismatch" },
    });
    expect(harness.http.calls).toEqual([]);
    expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    harness.assertExhausted();
  });

  it("accepts a connection whose observed peer matches the pinned address and port", async () => {
    const { harness, session: transportSession } = session(publicSuccessScript());

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome).toMatchObject({
      status: "success",
      evidence: { selectedAddress: PUBLIC_A },
    });
    expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    harness.assertExhausted();
  });
});

describe("mandatory transport budgets and incomplete outcomes", () => {
  it("enforces the cumulative hop budget before another DNS request", async () => {
    const { harness, session: transportSession } = session(publicSuccessScript(), { maxHops: 1 });
    const first = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    expect(first.status).toBe("success");
    const second = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    expect(second).toMatchObject({
      status: "incomplete",
      cause: { code: "hop-limit", details: { maxHops: 1 } },
    });
    expect(harness.resolver.calls).toHaveLength(1);
    harness.assertExhausted();
  });

  it("stops streamed bodies at the cumulative encoded-byte budget", async () => {
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      http: [{
        expect: { connectionId: "c1", url: URL_A, method: "GET" },
        outcome: {
          value: {
            status: 200,
            body: [
              { bytes: "1234" },
              { bytes: "5678" },
              { bytes: "must-not-be-read" },
            ],
          },
        },
      }],
    };
    const { harness, session: transportSession } = session(script, { maxResponseBytes: 6 });
    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    expect(outcome).toMatchObject({
      status: "incomplete",
      cause: { code: "response-too-large", details: { maxResponseBytes: 6 } },
    });
    expect(harness.http.bodies[0]).toMatchObject({ chunksRead: 2, bytesRead: 8 });
    expect(transportSession.usage.encodedBytes).toBe(6);
    harness.assertExhausted();
  });

  // The Slowloris mirror (LINK-xawdtzfd). Before the floor these two shapes ran
  // to the full session deadline holding a socket; the deadline bounded the
  // damage per request but not the resource hold, which is the attack.
  describe("minimum-throughput floor", () => {
    const SLOW_POLICY = {
      minThroughputBytes: 100,
      minThroughputWindowMs: 1_000,
      maxTotalTimeMs: 60_000,
    };

    /** Flush the microtask queue so fixture sleeps are registered before the clock moves. */
    const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

    async function run(
      body: readonly { readonly bytes: string; readonly delayMs?: number }[],
      stepMs: number,
      steps: number,
    ) {
      const script: TransportFixtureScript = {
        ...publicSuccessScript(),
        http: [{
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 200, body } },
        }],
      };
      const { harness, session: transportSession } = session(script, SLOW_POLICY);
      let settled = false;
      const pending = transportSession
        .fetch({ url: URL_A, authorization: authorization(URL_A) })
        .finally(() => {
          settled = true;
        });
      // Stop moving the clock the moment the outcome lands, so `clock.now()`
      // reads the instant the transport gave up rather than the end of the loop.
      for (let step = 0; step < steps && !settled; step++) {
        await flush();
        if (settled) break;
        harness.clock.advanceBy(stepMs);
      }
      await flush();
      return { harness, transportSession, outcome: await pending };
    }

    it("ends a trickling response before the session deadline", async () => {
      const trickle = Array.from({ length: 40 }, () => ({ bytes: "x", delayMs: 500 }));
      const { harness, transportSession, outcome } = await run(trickle, 500, 20);

      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: {
          code: "response-too-slow",
          details: { minThroughputBytes: 100, minThroughputWindowMs: 1_000 },
        },
      });
      // Ends inside the first window, not at the 60s deadline, and the socket goes with it.
      expect(harness.clock.now().getTime() - new Date("2026-07-17T12:00:00.000Z").getTime())
        .toBeLessThanOrEqual(SLOW_POLICY.minThroughputWindowMs);
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
      expect(transportSession.usage.encodedBytes).toBeLessThan(SLOW_POLICY.minThroughputBytes);
    });

    it("ends a fully silent response on the same path, not only at the deadline", async () => {
      const { harness, outcome } = await run([{ bytes: "x".repeat(200), delayMs: 30_000 }], 500, 4);

      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: { code: "response-too-slow" },
      });
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    });

    it("lets a slow but compliant response cross window boundaries and complete", async () => {
      const paced = Array.from({ length: 4 }, () => ({ bytes: "y".repeat(150), delayMs: 600 }));
      const { harness, outcome } = await run(paced, 300, 12);

      expect(outcome).toMatchObject({ status: "success" });
      // Guards against a vacuous pass: the stream must outlive at least two
      // window closes, so the floor was evaluated and cleared rather than skipped.
      expect(harness.clock.now().getTime() - new Date("2026-07-17T12:00:00.000Z").getTime())
        .toBeGreaterThanOrEqual(2 * SLOW_POLICY.minThroughputWindowMs);
    });

    it("rejects a non-positive floor or window", () => {
      expect(() => resolveTransportPolicy({ minThroughputBytes: 0 })).toThrow(RangeError);
      expect(() => resolveTransportPolicy({ minThroughputWindowMs: -1 })).toThrow(RangeError);
      expect(() => resolveTransportPolicy({ minThroughputWindowMs: 2_147_483_648 }))
        .toThrow(RangeError);
    });
  });

  it("bounds gzip expansion and rejects unknown content encodings", async () => {
    for (const unsupported of [false, true]) {
      const script: TransportFixtureScript = {
        ...publicSuccessScript(),
        http: [{
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: {
            value: unsupported
              ? { status: 200, headers: { "Content-Encoding": "compress" }, body: "body" }
              : {
                  status: 200,
                  headers: { "Content-Encoding": "gzip" },
                  body: gzipSync("x".repeat(4_096)),
                },
          },
        }],
      };
      const { harness, session: transportSession } = session(script, {
        maxDecompressedBytes: 128,
      });
      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });
      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: {
          code: unsupported
            ? "unsupported-content-encoding"
            : "decompressed-response-too-large",
        },
      });
      harness.assertExhausted();
    }
  });

  it("enforces one total session deadline with the deterministic clock", async () => {
    const { harness, session: transportSession } = session(
      {
        resolver: [
          {
            hostname: "origin.example",
            delayMs: 101,
            outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
          },
        ],
      },
      { maxTotalTimeMs: 100 },
    );
    const pending = transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    harness.clock.advanceBy(100);
    await expect(pending).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "timeout" },
    });
    expect(harness.connector.calls).toEqual([]);
    harness.assertExhausted();
  });

  it("counts encoded and decoded budgets cumulatively across authorized hops", async () => {
    const secondUrl = "https://origin.example/second";
    const { harness, session: transportSession } = session(
      {
        resolver: [
          {
            hostname: "origin.example",
            outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
          },
          {
            hostname: "origin.example",
            outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
          },
        ],
        connector: [
          {
            expect: {
              protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
              port: 443, serverName: "origin.example",
            },
            outcome: { value: connection("c1") },
          },
          {
            expect: {
              protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
              port: 443, serverName: "origin.example",
            },
            outcome: { value: connection("c2") },
          },
        ],
        http: [
          {
            expect: { connectionId: "c1", url: URL_A, method: "GET" },
            outcome: { value: { status: 200, body: "abc" } },
          },
          {
            expect: { connectionId: "c2", url: secondUrl, method: "GET" },
            outcome: { value: { status: 200, body: "def" } },
          },
        ],
      },
      { maxResponseBytes: 5, maxDecompressedBytes: 5 },
    );

    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({ status: "success" });
    await expect(transportSession.fetch({
      url: secondUrl,
      authorization: authorization(secondUrl),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "response-too-large" },
    });
    expect(transportSession.usage).toMatchObject({
      hops: 2,
      encodedBytes: 5,
      decompressedBytes: 3,
    });
    expect(harness.connector.closedConnectionIds).toEqual(["c1", "c2"]);
    harness.assertExhausted();
  });

  it("includes time between hops in the one total session deadline", async () => {
    const { harness, session: transportSession } = session(
      publicSuccessScript(),
      { maxTotalTimeMs: 100 },
    );
    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({ status: "success" });

    harness.clock.advanceBy(100);
    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "timeout" },
    });
    expect(harness.resolver.calls).toHaveLength(1);
    harness.assertExhausted();
  });

  it.each([
    {
      addresses: [] as const,
      code: "dns-not-found",
    },
    {
      addresses: [{ address: PUBLIC_A, family: 6 as const, ttlSeconds: 1 }],
      code: "dns-malformed",
    },
    {
      addresses: [{ address: "invalid", family: 4 as const, ttlSeconds: 1 }],
      code: "dns-malformed",
    },
  ])("turns $code DNS data into an explicit incomplete outcome", async ({ addresses, code }) => {
    const { harness, session: transportSession } = session({
      resolver: [{ hostname: "origin.example", outcome: { value: addresses } }],
    });
    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code },
    });
    expect(harness.connector.calls).toEqual([]);
    harness.assertExhausted();
  });

  it("preserves stable TLS and HTTP failure causes and closes opened connections", async () => {
    const tls = session({
      resolver: [{
        hostname: "origin.example",
        outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
      }],
      connector: [{
        expect: {
          protocol: "https:", hostname: "origin.example", address: PUBLIC_A,
          port: 443, serverName: "origin.example",
        },
        outcome: { failure: "tls-certificate" },
      }],
    });
    await expect(tls.session.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "tls-certificate" },
    });
    tls.harness.assertExhausted();

    const httpScript = publicSuccessScript();
    const http = session({
      ...httpScript,
      http: [{
        expect: { connectionId: "c1", url: URL_A, method: "GET" },
        outcome: { failure: "http-reset" },
      }],
    });
    await expect(http.session.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "http-reset" },
    });
    expect(http.harness.connector.closedConnectionIds).toEqual(["c1"]);
    http.harness.assertExhausted();
  });

  it("maps caller cancellation and stable fixture failures without leaking messages", async () => {
    const controller = new AbortController();
    const cancelled = session({
      resolver: [
        {
          hostname: "origin.example",
          delayMs: 50,
          outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 1 }] },
        },
      ],
    });
    const pending = cancelled.session.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).resolves.toMatchObject({
      status: "incomplete",
      cause: { code: "caller-aborted" },
    });
    cancelled.harness.assertExhausted();

    const failed = session({
      resolver: [
        { hostname: "origin.example", outcome: { failure: "dns-not-found" } },
      ],
    });
    const outcome = await failed.session.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });
    expect(outcome).toEqual(expect.objectContaining({
      status: "incomplete",
      cause: { code: "dns-not-found" },
    }));
    expect(JSON.stringify(outcome)).not.toContain("scripted fixture failure");
    failed.harness.assertExhausted();
  });
});

/**
 * LINK-ktjbhvqd — the total deadline has to bound the *reported* success, not
 * only the start of the last operation.
 *
 * `decodeResponseBody` runs zlib's synchronous entry points, so while it works
 * the event loop is blocked and the timer racing the operation cannot fire. A
 * transport that only races the deadline therefore returns `success` after
 * `maxTotalTimeMs` has already passed. These tests use the real wall clock —
 * with a fixture clock the decode costs zero measured time and the bug is
 * invisible — while the fixture ports stay scripted with no step delays, so the
 * only elapsed time in the session is the decode itself.
 */
describe("total deadline during synchronous response decoding", () => {
  const DECODERS = [
    { encoding: "gzip", compress: gzipSync },
    { encoding: "deflate", compress: deflateSync },
    { encoding: "br", compress: brotliCompressSync },
  ] as const;

  /** Large enough that every decoder needs milliseconds, not microseconds. */
  const DECODED_BYTES = 16 * 1024 * 1024;

  function realClockSession(
    script: TransportFixtureScript,
    policy: Parameters<typeof createSafeTransport>[0]["policy"],
  ) {
    const harness = new TransportFixtureHarness(script);
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: new SystemClock(),
      ...(policy === undefined ? {} : { policy }),
    });
    return { harness, session: transport.createSession() };
  }

  function encodedScript(encoding: string, encoded: Uint8Array): TransportFixtureScript {
    return {
      ...publicSuccessScript(),
      http: [{
        expect: { connectionId: "c1", url: URL_A, method: "GET" },
        outcome: {
          value: { status: 200, headers: { "Content-Encoding": encoding }, body: encoded },
        },
      }],
    };
  }

  it.each(DECODERS)(
    "refuses a $encoding body whose decode finishes after maxTotalTimeMs",
    async ({ encoding, compress }) => {
      const raw = new Uint8Array(DECODED_BYTES).fill(0x78);
      const encoded = new Uint8Array(compress(raw));
      const { harness, session: transportSession } = realClockSession(
        encodedScript(encoding, encoded),
        { maxTotalTimeMs: 1, maxDecompressedBytes: 32 * 1024 * 1024 },
      );

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({ status: "incomplete", cause: { code: "timeout" } });
      // Guards against a vacuous pass: the attempt must have reached and
      // completed the decode, and must have overrun the deadline doing it —
      // not timed out earlier on some unrelated path.
      expect(transportSession.usage.decompressedBytes).toBe(DECODED_BYTES);
      expect(transportSession.usage.elapsedMs).toBeGreaterThan(1);
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
      harness.assertExhausted();
    },
  );

  it.each(DECODERS)(
    "still completes a $encoding body whose decode finishes inside maxTotalTimeMs",
    async ({ encoding, compress }) => {
      const raw = new Uint8Array(64 * 1024).fill(0x79);
      const encoded = new Uint8Array(compress(raw));
      const { harness, session: transportSession } = realClockSession(
        encodedScript(encoding, encoded),
        undefined,
      );

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({
        status: "success",
        response: { status: 200, decompressedBytes: raw.byteLength },
      });
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
      harness.assertExhausted();
    },
  );

  it("keeps the decoded-byte cap ahead of the deadline check", async () => {
    const raw = new Uint8Array(DECODED_BYTES).fill(0x78);
    const { harness, session: transportSession } = realClockSession(
      encodedScript("gzip", new Uint8Array(gzipSync(raw))),
      { maxTotalTimeMs: 1, maxDecompressedBytes: 1_024 },
    );

    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "incomplete",
      cause: {
        code: "decompressed-response-too-large",
        details: { maxDecompressedBytes: 1_024 },
      },
    });
    expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    harness.assertExhausted();
  });
});
