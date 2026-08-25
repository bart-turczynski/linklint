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
import { pinDestination } from "../src/transport/pin.js";
import type { DnsAddress, ResolverPort } from "../src/transport/types.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../src/testing/index.js";

const PUBLIC_A = "93.184.216.34";
const PUBLIC_B = "93.184.216.35";
const PUBLIC_V6 = "2606:4700:4700::1111";
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
    expect(() => resolveTransportPolicy({ maxResponseHeaderBytes: 0 })).toThrow(RangeError);
    expect(() => resolveTransportPolicy({ maxResponseHeaderFields: 1.5 })).toThrow(RangeError);
    expect(resolveTransportPolicy(undefined)).toEqual(DEFAULT_TRANSPORT_POLICY);
  });
});

/**
 * F11 (`LINK-rbghrpru`) — the pinned address is a member of the set the hop's own
 * resolution returned.
 *
 * The docs claimed an "all-answer" / "every DNS answer" policy, but nothing pinned the
 * positive half of it. The existing prohibited-answer case pins only the NEGATIVE (a
 * mixed set connects to nothing), and every other case in this file resolves a
 * single-element answer array — so with one answer, "selected is a member of the
 * returned set" is true by arithmetic rather than by the code. These cases are the
 * first in the suite with TWO ALLOWED answers, which is what makes first-allowed
 * selection and set membership separable properties at all.
 *
 * They drive {@link pinDestination} directly because it is the seam `safeFetch` and the
 * TLS-observe path share; a case written against the fetch session alone would cover
 * one of the two. The last case then re-checks the property end to end, against the
 * address the connector actually received.
 */
describe("pinned address membership in the resolver-returned set (LINK-rbghrpru)", () => {
  function fixedResolver(answers: readonly DnsAddress[]): ResolverPort & {
    readonly calls: string[];
  } {
    const calls: string[] = [];
    return {
      calls,
      resolve: ({ hostname }) => {
        calls.push(hostname);
        return Promise.resolve(answers.map((answer) => ({ ...answer })));
      },
    };
  }

  function answer(address: string, family: 4 | 6 = 4): DnsAddress {
    return { address, family, ttlSeconds: 60 };
  }

  const allowedSets: readonly (readonly DnsAddress[])[] = [
    [answer(PUBLIC_A), answer(PUBLIC_B)],
    [answer(PUBLIC_B), answer(PUBLIC_A)],
    [answer(PUBLIC_V6, 6), answer(PUBLIC_A)],
    [answer(PUBLIC_A), answer(PUBLIC_V6, 6), answer(PUBLIC_B)],
  ];

  it.each(allowedSets.map((set) => [set.map((a) => a.address).join(","), set] as const))(
    "pins a member of the returned set and reports the set verbatim: %s",
    async (_label, set) => {
      const resolver = fixedResolver(set);
      const result = await pinDestination(
        resolver,
        "origin.example",
        new AbortController().signal,
      );

      expect(result.kind).toBe("pinned");
      if (result.kind !== "pinned") return;
      // The recorded set is exactly what resolution returned — same members, same
      // order, nothing added and nothing dropped.
      expect(result.resolvedAddresses).toEqual(set.map(({ address }) => address));
      // The claim itself: the pin is drawn from that set.
      expect(result.resolvedAddresses).toContain(result.selected.address);
      // …and specifically the first allowed member, which is the selection rule.
      expect(result.selected).toEqual(set[0]);
      expect(resolver.calls).toEqual(["origin.example"]);
    },
  );

  it("pins the first ALLOWED member when an earlier answer is only unroutable, never a substitute", async () => {
    // Guards the inverse mistake: with more than one allowed answer available, a
    // prohibited member must not cause a fallback to some other address — the whole
    // set is refused, and nothing is selected.
    const resolver = fixedResolver([answer("169.254.169.254"), answer(PUBLIC_A), answer(PUBLIC_B)]);
    const result = await pinDestination(resolver, "origin.example", new AbortController().signal);

    expect(result).toMatchObject({
      kind: "prohibited",
      address: "169.254.169.254",
      category: "ip_cloud_metadata",
    });
    expect(result.resolvedAddresses).toEqual(["169.254.169.254", PUBLIC_A, PUBLIC_B]);
    expect(result).not.toHaveProperty("selected");
  });

  it("pins a literal address to itself and asks the resolver nothing", async () => {
    const resolver = fixedResolver([answer(PUBLIC_B)]);
    const result = await pinDestination(resolver, PUBLIC_A, new AbortController().signal);

    expect(result).toMatchObject({ kind: "pinned", resolvedAddresses: [PUBLIC_A] });
    if (result.kind !== "pinned") return;
    expect(result.resolvedAddresses).toContain(result.selected.address);
    expect(resolver.calls).toEqual([]);
  });

  it("hands the connector an address from the recorded set on the full fetch path", async () => {
    const { harness, session: transportSession } = session({
      startTime: "2026-07-17T12:00:00.000Z",
      resolver: [
        {
          hostname: "origin.example",
          outcome: {
            value: [
              { address: PUBLIC_A, family: 4, ttlSeconds: 60 },
              { address: PUBLIC_B, family: 4, ttlSeconds: 60 },
            ],
          },
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
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 200, body: "ok" } },
        },
      ],
    });

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome.status).toBe("success");
    expect(outcome.evidence.resolvedAddresses).toEqual([PUBLIC_A, PUBLIC_B]);
    expect(harness.connector.calls).toHaveLength(1);
    const connected = harness.connector.calls[0]!.address;
    // Read the claim off the evidence the caller is given, not off a literal: the
    // address the connector received must appear in the set that was classified.
    expect(outcome.evidence.resolvedAddresses).toContain(connected);
    expect(outcome.evidence.selectedAddress).toBe(connected);
    harness.assertExhausted();
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

  /**
   * The response-header budget (`LINK-vwnccgxf`).
   *
   * These cases drive the PORT-AGNOSTIC seam deliberately: the fixture HTTP port
   * is exactly the shape of a caller-supplied port, and the built-in adapter's
   * `maxHeaderSize` cannot reach it. If enforcement lived only in
   * `transport/node.ts`, every case here would return `success`.
   *
   * There is no scripted `FixtureFailureCode` for this cause, on purpose. It is
   * derived from header CONTENT rather than raised by a port, so a fixture can
   * produce it authentically by scripting an oversized head; a scripted shortcut
   * would let a fixture claim the budget tripped without content that trips it.
   */
  describe("response-header budget", () => {
    function headerScript(
      headers: Readonly<Record<string, string | readonly string[]>>,
    ): TransportFixtureScript {
      return {
        ...publicSuccessScript(),
        http: [{
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 200, headers, body: "must-not-be-read" } },
        }],
      };
    }

    it("stops an oversized header block before the body is read", async () => {
      const script = headerScript({ "x-pad": "a".repeat(4_000) });
      const { harness, session: transportSession } = session(script, {
        maxResponseHeaderBytes: 512,
      });

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: {
          code: "response-headers-too-large",
          details: { maxResponseHeaderBytes: 512, maxResponseHeaderFields: 128 },
        },
      });
      // The head is refused without spending any body work, and the socket goes
      // with it rather than being left for the deadline to reap.
      expect(harness.http.bodies[0]).toMatchObject({ chunksRead: 0, bytesRead: 0 });
      expect(transportSession.usage.encodedBytes).toBe(0);
      expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
      harness.assertExhausted();
    });

    it("stops a header block that is small but has too many fields", async () => {
      // Well inside the byte budget: the field count is a separate axis because a
      // byte cap alone lets thousands of tiny fields through.
      const many: Record<string, string> = {};
      for (let index = 0; index < 40; index++) many[`x-${index}`] = "v";
      const { harness, session: transportSession } = session(headerScript(many), {
        maxResponseHeaderFields: 8,
      });

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: {
          code: "response-headers-too-large",
          details: { maxResponseHeaderFields: 8 },
        },
      });
      harness.assertExhausted();
    });

    it("counts repeated occurrences of one name as separate fields", async () => {
      // Guards against measuring `Object.keys(...).length`: fifty Set-Cookie
      // values arrive under a single key but cost fifty fields on the wire.
      const cookies = Array.from({ length: 50 }, (_unused, index) => `s${index}=1`);
      const { harness, session: transportSession } = session(
        headerScript({ "set-cookie": cookies }),
        { maxResponseHeaderFields: 10 },
      );

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({
        status: "incomplete",
        cause: { code: "response-headers-too-large" },
      });
      harness.assertExhausted();
    });

    it("lets an ordinary header block through under the defaults", async () => {
      const { harness, session: transportSession } = session(headerScript({
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "set-cookie": ["a=1; Path=/", "b=2; Path=/"],
      }));

      const outcome = await transportSession.fetch({
        url: URL_A,
        authorization: authorization(URL_A),
      });

      expect(outcome).toMatchObject({ status: "success" });
      harness.assertExhausted();
    });

    it("rejects a non-positive header budget", () => {
      expect(() => resolveTransportPolicy({ maxResponseHeaderBytes: -1 })).toThrow(RangeError);
      expect(() => resolveTransportPolicy({ maxResponseHeaderFields: 0 })).toThrow(RangeError);
    });
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

  /**
   * Large enough that every decoder needs tens of milliseconds, not
   * microseconds: measured 20-37 ms per attempt inside this suite.
   */
  const DECODED_BYTES = 32 * 1024 * 1024;

  /**
   * The session deadline these tests run against.
   *
   * LINK-dvshjpik. It has to sit inside a window with headroom at both ends,
   * because both ends are wall-clock races:
   *
   *  - Below it: the session budget starts running at `createSession()`, so a
   *    deadline shorter than the gap between constructing the session and
   *    entering `fetch` is already spent before any work starts, and the
   *    attempt times out at the pre-flight check without ever reaching the
   *    decode. That gap measures ~0.07 ms here, but the original
   *    `maxTotalTimeMs: 1` left no room for the millisecond tick to land
   *    inside it, and these tests failed ~7% of runs with
   *    `usage.decompressedBytes` still 0.
   *  - Above it: the decode has to actually overrun the deadline, or the
   *    refusal tests prove nothing.
   *
   * 5 ms is ~70x the setup gap and ~4x under the fastest attempt observed
   * (20.2 ms). Neither violation can pass vacuously: too short and the guards
   * below see `decompressedBytes` of 0, too long and the outcome is `success`.
   */
  const DEADLINE_MS = 5;

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
        { maxTotalTimeMs: DEADLINE_MS, maxDecompressedBytes: 64 * 1024 * 1024 },
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
      expect(transportSession.usage.elapsedMs).toBeGreaterThanOrEqual(DEADLINE_MS);
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

  /**
   * The deadline check runs after the decode and after the decoded-byte budget
   * is charged, so an over-cap body reports the cap rather than being rewritten
   * into a timeout. This pins that ordering under the same tight deadline the
   * refusal tests above use. The cap short-circuits the decode within
   * microseconds — zlib stops at `maxOutputLength`, it does not inflate the
   * whole body first — and everything from the deadline's pre-flight check to
   * the decode is a microtask chain over scripted fixtures, so the deadline is
   * still unspent when the cap error is raised.
   *
   * What this deliberately does not pin is the case where the cap and the
   * deadline are exhausted *together*. The implementation defines no precedence
   * there: the cap error and the raced `DeadlineError` reach `fetch`'s catch by
   * different routes, and which one is reported depends on whether anything
   * yields to the event loop between the decode throwing and the race settling.
   * Pinning an order for that case would pin the fixture's scheduling, not the
   * transport's contract. Nor is there an elapsed assertion here: `usage` can
   * only be read after the outcome resolves, so a bound on it would measure the
   * harness's own scheduling rather than the deadline's state at the moment the
   * cap fired — it read 6 ms under a loaded full-suite run (LINK-dvshjpik).
   */
  it("reports the decoded-byte cap, not a timeout, when the cap is hit inside the deadline", async () => {
    const raw = new Uint8Array(DECODED_BYTES).fill(0x78);
    const { harness, session: transportSession } = realClockSession(
      encodedScript("gzip", new Uint8Array(gzipSync(raw))),
      { maxTotalTimeMs: DEADLINE_MS, maxDecompressedBytes: 1_024 },
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
    // Guards against a vacuous pass: the attempt reached the decode and charged
    // the cap, rather than timing out somewhere ahead of it.
    expect(transportSession.usage.decompressedBytes).toBe(1_024);
    expect(harness.connector.closedConnectionIds).toEqual(["c1"]);
    harness.assertExhausted();
  });
});

/**
 * LINK-syeupoav — an empty body carrying a `Content-Encoding` is an empty body,
 * not a decompression failure.
 *
 * These drive the whole transport, so they pin the reported outcome and the
 * budget accounting rather than the decoder in isolation. Every shape here is
 * one a spec-conformant origin actually produces: RFC 9110 9.3.2 requires a
 * HEAD response to carry the header fields it would send for a GET,
 * `Content-Encoding` included, with no body, and nginx, Apache and Cloudflare
 * all comply. A 204 and an empty 200 reach the same decode on GET, which is why
 * the fix belongs in the decoder and not in a HEAD special case.
 */
describe("empty response bodies declaring a content encoding", () => {
  interface EmptyCase {
    readonly label: string;
    readonly method: "GET" | "HEAD";
    readonly status: number;
    readonly headers: Record<string, string>;
  }

  const CASES: readonly EmptyCase[] = [
    {
      label: "a HEAD response against a gzip resource",
      method: "HEAD",
      status: 200,
      headers: { "Content-Encoding": "gzip", "Content-Type": "text/html" },
    },
    {
      label: "a 204 carrying a gzip encoding",
      method: "GET",
      status: 204,
      headers: { "Content-Encoding": "gzip" },
    },
    {
      label: "an empty 200 carrying a gzip encoding",
      method: "GET",
      status: 200,
      headers: { "Content-Encoding": "gzip", "Content-Length": "0" },
    },
    {
      label: "an empty 200 carrying a brotli encoding",
      method: "GET",
      status: 200,
      headers: { "Content-Encoding": "br", "Content-Length": "0" },
    },
  ];

  it.each(CASES)("succeeds with an empty body for $label", async ({ method, status, headers }) => {
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      http: [{
        expect: { connectionId: "c1", url: URL_A, method },
        outcome: { value: { status, headers, body: new Uint8Array(0) } },
      }],
    };
    const { harness, session: transportSession } = session(script);

    const outcome = await transportSession.fetch({
      url: URL_A,
      method,
      authorization: authorization(URL_A),
    });

    expect(outcome).toMatchObject({
      status: "success",
      response: { status, encodedBytes: 0, decompressedBytes: 0 },
    });
    expect((outcome as { response: { body: Uint8Array } }).response.body.byteLength).toBe(0);
    expect(transportSession.usage.decompressedBytes).toBe(0);
    harness.assertExhausted();
  });

  /**
   * The guard sits above the encoding parse, so an empty body under an encoding
   * the transport cannot decode is still an empty body. Nothing can be smuggled
   * in zero bytes, and `unsupported-content-encoding` would be as spurious a
   * failure here as `decompression-error` was.
   */
  it("succeeds for an empty body under an unsupported encoding", async () => {
    const script: TransportFixtureScript = {
      ...publicSuccessScript(),
      http: [{
        expect: { connectionId: "c1", url: URL_A, method: "GET" },
        outcome: {
          value: { status: 204, headers: { "Content-Encoding": "compress" }, body: new Uint8Array(0) },
        },
      }],
    };
    const { harness, session: transportSession } = session(script);

    await expect(transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    })).resolves.toMatchObject({
      status: "success",
      response: { status: 204, decompressedBytes: 0 },
    });
    harness.assertExhausted();
  });
});

describe("certificate evidence from the hop's own handshake (LINK-boqmfrcn)", () => {
  const LEAF = {
    subject: "CN=origin.example",
    issuer: "CN=linklint test CA",
    serialNumber: "46F095011A92E656824857648CC5BFCF09E580E5",
    subjectAltNames: ["origin.example"],
    policyOids: [],
    assuranceLevel: "unknown",
    notBefore: "2026-07-27T10:54:08.000Z",
    notAfter: "2126-07-03T10:54:08.000Z",
    selfIssued: false,
  } as const;

  // FIXTURE, not live: this pins the connection -> evidence wiring only. That the
  // connector recovers a real leaf off a real handshake is pinned separately and
  // against loopback, in `node-transport-tls-live.test.ts`.
  it("carries the leaf through to the evidence the caller is given", async () => {
    const { harness, session: transportSession } = session({
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
          outcome: {
            value: {
              ...connection("c1"),
              tls: {
                authorized: true,
                serverName: "origin.example",
                peerDnsNames: ["origin.example"],
                certificate: LEAF,
              },
            },
          },
        },
      ],
      http: [
        {
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 200, body: "ok" } },
        },
      ],
    });

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome.status).toBe("success");
    expect(outcome.evidence.tls?.authorized).toBe(true);
    expect(outcome.evidence.tls?.certificate).toEqual(LEAF);
    harness.assertExhausted();
  });

  // The gap this closes is evidence-shaped, so the absence case matters as much as
  // the presence one: a connector that recovers no leaf must yield evidence with no
  // certificate, NOT an empty or partially-filled one.
  it("omits the certificate when the connector recovered none", async () => {
    const { harness, session: transportSession } = session({
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
          expect: { connectionId: "c1", url: URL_A, method: "GET" },
          outcome: { value: { status: 200, body: "ok" } },
        },
      ],
    });

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome.status).toBe("success");
    expect(outcome.evidence.tls?.authorized).toBe(true);
    expect(outcome.evidence.tls?.certificate).toBeUndefined();
    harness.assertExhausted();
  });
});

describe("certificate evidence is never published for an unverified peer", () => {
  // Pins the claim in docs/safe-transport.md that a populated tls block never
  // describes an unverified peer: the identity check runs BEFORE the record, so a
  // mismatched peer yields no tls evidence at all rather than evidence marked bad.
  it("publishes no tls evidence when the peer identity does not match", async () => {
    const { harness, session: transportSession } = session({
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
          outcome: {
            value: {
              ...connection("c1"),
              tls: {
                authorized: true,
                // The peer answered to a different name than the hop asked for.
                serverName: "attacker.example",
                peerDnsNames: ["attacker.example"],
                certificate: {
                  subject: "CN=attacker.example",
                  issuer: "CN=linklint test CA",
                  serialNumber: "00",
                  subjectAltNames: ["attacker.example"],
                  policyOids: [],
                  assuranceLevel: "unknown",
                  notBefore: "2026-07-27T10:54:08.000Z",
                  notAfter: "2126-07-03T10:54:08.000Z",
                  selfIssued: false,
                },
              },
            },
          },
        },
      ],
      http: [],
    });

    const outcome = await transportSession.fetch({
      url: URL_A,
      authorization: authorization(URL_A),
    });

    expect(outcome.status).toBe("incomplete");
    expect(outcome.evidence.tls).toBeUndefined();
    harness.assertExhausted();
  });
});
