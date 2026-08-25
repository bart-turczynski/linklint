/**
 * Caller-supplied request header values at the L0 boundary.
 *
 * `SafeFetchRequest.headers` is PUBLIC and `transport/headers.ts` forwards three
 * of its fields verbatim — `accept`, `accept-language`, `user-agent`. Its filter
 * is `!/[\0\r\n]/.test(value)`, a request-SPLITTING guard. Node's line is a
 * different one: `http.request` validates the whole header block synchronously
 * inside the `ClientRequest` constructor against `[^\t\x20-\x7e\x80-\xff]`, so
 * anything past Latin-1 is refused before the request object exists — before any
 * `error` listener can be attached, and therefore outside every asynchronous
 * mapper the transport owns.
 *
 * The two lines do not agree, and the gap between them is caller-reachable with
 * an entirely ordinary value: `accept-language: "日本語"` passes the splitting
 * guard, reaches `http.request`, and escapes L0 as a raw `TypeError`
 * (`ERR_INVALID_CHAR`) in place of the typed `SafeFetchOutcome` every caller
 * switches on.
 *
 * These tests drive the real `node:net`/`node:http` wiring against a loopback
 * server, because no fixture can prove anything about a throw that happens
 * inside Node's own constructor. They reach the ports directly for the same
 * reason `node-transport-live.test.ts` does: L0 policy correctly refuses
 * loopback addresses above this layer.
 */
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import { destinationHeaders } from "../src/transport/headers.js";
import { NodeConnectionPorts } from "../src/transport/node.js";
import { createSafeTransport } from "../src/transport/index.js";
import { TransportFixtureHarness } from "../src/testing/index.js";

let server: Server | undefined;

afterEach(async () => {
  const running = server;
  server = undefined;
  if (running === undefined) return;
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

interface ObservedRequest {
  count: number;
  headers: Record<string, string | string[] | undefined>;
}

async function startServer(observed: ObservedRequest): Promise<number> {
  const created = createServer((req, res) => {
    observed.count += 1;
    observed.headers = req.headers;
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

interface TypedFailure {
  readonly name: string;
  readonly code: unknown;
  readonly message: string;
}

async function failureOf(promise: Promise<unknown>): Promise<TypedFailure> {
  try {
    await promise;
  } catch (error) {
    const failure = error as { name?: unknown; code?: unknown; message?: unknown };
    return {
      name: typeof failure.name === "string" ? failure.name : "",
      code: failure.code,
      message: typeof failure.message === "string" ? failure.message : "",
    };
  }
  throw new Error("expected a rejection");
}

/**
 * One caller request through the real ports, with the real header builder in
 * front of it — so what is under test is the whole public path from
 * `SafeFetchRequest.headers` to the wire, not a hand-assembled header map.
 */
async function fetchWithCallerHeaders(
  port: number,
  callerHeaders: Readonly<Record<string, string>>,
): Promise<number> {
  const ports = new NodeConnectionPorts();
  const connection = await ports.connect({
    protocol: "http:",
    hostname: "origin.example",
    address: "127.0.0.1",
    port,
  });
  try {
    const response = await ports.request({
      connectionId: connection.id,
      url: `http://origin.example:${port}/probe`,
      method: "GET",
      headers: destinationHeaders("origin.example", callerHeaders),
    });
    for await (const _chunk of response.body) {
      // Drain so the socket is not abandoned mid-body.
    }
    return response.status;
  } finally {
    ports.close(connection.id);
  }
}

describe("caller header values Node refuses (live loopback)", () => {
  /**
   * `日本語` is the whole point: it is not an exotic probe, it is what a caller
   * inspecting a Japanese-language destination would reasonably send. Before
   * this it left the boundary as `TypeError [ERR_INVALID_CHAR]`.
   */
  it.each([
    ["a non-Latin-1 Accept-Language", { "Accept-Language": "日本語" }],
    ["a value one codepoint past Latin-1", { "Accept-Language": '"vĀ"' }],
    ["a non-Latin-1 User-Agent", { "User-Agent": "linklint/1.0 (日本)" }],
    ["a DEL in Accept", { Accept: "text/\x7fhtml" }],
    ["a bare control character", { "Accept-Language": "de\x01DE" }],
  ])("types %s instead of leaking a raw TypeError", async (_case, callerHeaders) => {
    const observed: ObservedRequest = { count: 0, headers: {} };
    const port = await startServer(observed);

    const failure = await failureOf(fetchWithCallerHeaders(port, callerHeaders));

    expect(failure.name).toBe("NodePortFailure");
    expect(failure.code).toBe("http-malformed");
    // Nothing from Node's message survives, and the refused value is the one
    // thing a failure may never echo back.
    for (const value of Object.values(callerHeaders)) {
      expect(failure.message).not.toContain(value);
    }
    // Refused at this boundary, not at the wire: the destination never saw a
    // request at all.
    expect(observed.count).toBe(0);
  });

  /**
   * THE CONTROL, and the reason the fix is not "narrow to ASCII".
   *
   * The wire line for a header field value is Latin-1, not ASCII. `ü` is a
   * legal `obs-text` octet and an ordinary `Accept-Language` carries commas,
   * semicolons and `q=` weights. A guard drawn narrower than Node's would
   * refuse values a caller is entitled to send, which is a worse defect than the
   * one being fixed. Every value below must reach the destination BYTE FOR BYTE.
   */
  it("passes every Latin-1 caller value to the wire unchanged", async () => {
    const observed: ObservedRequest = { count: 0, headers: {} };
    const port = await startServer(observed);

    const status = await fetchWithCallerHeaders(port, {
      "Accept-Language": "de-DE, fr;q=0.9",
      "User-Agent": "linklint/1.0 (Grüße; ÿ)",
      Accept: "text/html;q=0.9, */*",
    });

    expect(status).toBe(200);
    expect(observed.count).toBe(1);
    expect(observed.headers["accept-language"]).toBe("de-DE, fr;q=0.9");
    expect(observed.headers["user-agent"]).toBe("linklint/1.0 (Grüße; ÿ)");
    expect(observed.headers.accept).toBe("text/html;q=0.9, */*");
  });

  /**
   * The header builder's own line is unchanged and stays a SPLITTING guard: a
   * CR/LF/NUL value is dropped before it reaches any HTTP port, including a
   * caller-supplied one. Sendability is a different question, answered by the
   * adapter that owns the wire.
   */
  it("still drops a splitting-shaped value at the port-agnostic header builder", () => {
    const built = destinationHeaders("origin.example", {
      "Accept-Language": "en\r\nX-Injected: 1",
      "User-Agent": "linklint/1.0 (Grüße)",
    });

    expect(built["accept-language"]).toBeUndefined();
    expect(built["user-agent"]).toBe("linklint/1.0 (Grüße)");
  });
});

describe("typed port failures reach the outcome contract", () => {
  /**
   * Closes the chain the live tests above stop short of. `NodeConnectionPorts`
   * cannot be driven through `session.fetch` on loopback — L0 policy refuses the
   * address, correctly — so the last link is asserted on the fixture harness:
   * an HTTP port that fails with `http-malformed` becomes an `incomplete`
   * outcome carrying that cause, never an escaped exception.
   */
  it("maps an http-malformed port failure to an incomplete outcome", async () => {
    const url = "https://origin.example/start";
    const harness = new TransportFixtureHarness({
      startTime: "2026-07-17T12:00:00.000Z",
      resolver: [
        {
          hostname: "origin.example",
          outcome: { value: [{ address: "93.184.216.34", family: 4, ttlSeconds: 60 }] },
        },
      ],
      connector: [
        {
          expect: {
            protocol: "https:",
            hostname: "origin.example",
            address: "93.184.216.34",
            port: 443,
            serverName: "origin.example",
          },
          outcome: {
            value: {
              id: "c1",
              protocol: "https:",
              remoteAddress: "93.184.216.34",
              remotePort: 443,
              tls: {
                authorized: true,
                serverName: "origin.example",
                peerDnsNames: ["origin.example"],
              },
            },
          },
        },
      ],
      http: [
        {
          expect: { connectionId: "c1", url, method: "GET" },
          outcome: { failure: "http-malformed" },
        },
      ],
    });
    const transportSession = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    }).createSession();

    const outcome = await transportSession.fetch({
      url,
      authorization: { kind: "destination-fetch", url },
      headers: { "Accept-Language": "日本語" },
    });

    expect(outcome.status).toBe("incomplete");
    if (outcome.status === "incomplete") expect(outcome.cause.code).toBe("http-malformed");
    harness.assertExhausted();
  });

  /**
   * The contrast, and why typing the failure inside the adapter is worth doing
   * rather than leaving to the layer above. An HTTP port that rejects with a raw
   * Node error is not an escaped exception at the session boundary — it becomes
   * `http-error`. But `http-error` is what a socket fault reports, so the caller
   * cannot tell "your header is not sendable, fix it" from "the destination
   * misbehaved, retry". That collapse is the defect this unit removes.
   */
  it("would report a raw Node error as the generic http-error", async () => {
    const url = "https://origin.example/start";
    const harness = new TransportFixtureHarness({
      startTime: "2026-07-17T12:00:00.000Z",
      resolver: [
        {
          hostname: "origin.example",
          outcome: { value: [{ address: "93.184.216.34", family: 4, ttlSeconds: 60 }] },
        },
      ],
      connector: [
        {
          expect: {
            protocol: "https:",
            hostname: "origin.example",
            address: "93.184.216.34",
            port: 443,
            serverName: "origin.example",
          },
          outcome: {
            value: {
              id: "c1",
              protocol: "https:",
              remoteAddress: "93.184.216.34",
              remotePort: 443,
              tls: {
                authorized: true,
                serverName: "origin.example",
                peerDnsNames: ["origin.example"],
              },
            },
          },
        },
      ],
    });
    const invalidChar = Object.assign(new TypeError("Invalid character in header content"), {
      code: "ERR_INVALID_CHAR",
    });
    const transportSession = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: { request: () => Promise.reject(invalidChar) },
      clock: harness.clock,
    }).createSession();

    const outcome = await transportSession.fetch({
      url,
      authorization: { kind: "destination-fetch", url },
    });

    expect(outcome.status).toBe("incomplete");
    if (outcome.status === "incomplete") expect(outcome.cause.code).toBe("http-error");
  });
});

describe("synchronous connect throws (live loopback)", () => {
  /**
   * `openSocket` has the same bare-call-in-executor shape as `request` had:
   * `net.connect` / `tls.connect` validate their options synchronously, so a
   * refused one throws before any `error` listener exists.
   *
   * No path through `session.fetch` can reach it today — `effectivePort` reads a
   * WHATWG-parsed port, which cannot be out of range — but the CLASS of failure
   * is not hypothetical: Node 26 added `ERR_INVALID_ARG_VALUE` for an IP
   * `servername` to this exact call, and only an explicit guard in
   * `transport/node.ts` keeps it from escaping on a gated major. This pins the
   * catch behind that guard, at the port surface where it IS reachable.
   */
  it.each([
    ["http:" as const],
    ["https:" as const],
  ])("types a %s connect option Node refuses synchronously", async (protocol) => {
    const ports = new NodeConnectionPorts();

    const failure = await failureOf(
      ports.connect({
        protocol,
        hostname: "origin.example",
        address: "127.0.0.1",
        // Out of range, so `net`/`tls` throw `ERR_SOCKET_BAD_PORT` from the
        // constructor. Nothing is ever sent, and no port is contacted.
        port: 99_999,
        ...(protocol === "https:" ? { serverName: "origin.example" } : {}),
      }),
    );

    expect(failure.name).toBe("NodePortFailure");
    expect(failure.code).toBe("connect-error");
  });
});
