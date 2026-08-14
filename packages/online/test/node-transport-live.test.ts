/**
 * Live coverage for the real Node connector and HTTP/1.1 port.
 *
 * Every other transport test injects the deterministic fixture harness, so the
 * concrete `node:net` / `node:http` wiring in `transport/node.ts` had no
 * behavioral coverage at all. That gap hid a total failure: `createConnection`
 * passed alongside `agent: false` is ignored, so the unresolvable placeholder
 * host reached getaddrinfo and every request failed with ENOTFOUND.
 *
 * Uses a loopback server, so it needs no external network. It drives the ports
 * directly because L0 policy correctly refuses loopback addresses above this
 * layer.
 */
import { createServer, type Server } from "node:http";
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { decodeResponseBody } from "../src/transport/decompression.js";
import { NodeConnectionPorts } from "../src/transport/node.js";
import {
  RUNTIME_GLOBAL_PROXY_SUPPORTED,
  deadLoopbackPort,
  globalAgentIsProxied,
  runUnderStartupProxyEnv,
  withRuntimeGlobalProxy,
} from "./proxy-isolation-harness.js";

let server: Server | undefined;

afterEach(async () => {
  const running = server;
  server = undefined;
  if (running === undefined) return;
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

async function startServer(
  handler: (path: string, headers: Record<string, string | string[] | undefined>) => {
    status: number;
    body: string | Buffer;
    headers?: Record<string, string | string[]>;
  },
): Promise<number> {
  const created = createServer((req, res) => {
    const { status, body, headers } = handler(req.url ?? "/", req.headers);
    res.writeHead(status, { "content-type": "text/plain", ...headers });
    res.end(body);
  });
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

async function readBody(body: AsyncIterable<Uint8Array>): Promise<string> {
  return Buffer.from(await readBodyBytes(body)).toString("utf8");
}

async function readBodyBytes(body: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) chunks.push(chunk);
  return new Uint8Array(Buffer.concat(chunks));
}

describe("node transport ports (live loopback)", () => {
  it("issues a request over the pinned socket instead of resolving the placeholder host", async () => {
    const port = await startServer(() => ({ status: 200, body: "hello" }));
    const ports = new NodeConnectionPorts();

    const connection = await ports.connect({
      protocol: "http:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
    });

    try {
      // Both peer fields come off the socket. The adapter has no fallback to the
      // requested address/port to fill them in with (LINK-abozdqtp).
      expect(connection.remoteAddress).toBe("127.0.0.1");
      expect(connection.remotePort).toBe(port);

      const response = await ports.request({
        connectionId: connection.id,
        url: `http://origin.example:${port}/probe?q=1`,
        method: "GET",
        headers: { host: "origin.example" },
      });

      expect(response.status).toBe(200);
      expect(await readBody(response.body)).toBe("hello");
    } finally {
      ports.close(connection.id);
    }
  });

  it("sends the caller's Host header and request target, not the pinned placeholder", async () => {
    let seenPath = "";
    let seenHost: string | string[] | undefined;
    const port = await startServer((path, headers) => {
      seenPath = path;
      seenHost = headers.host;
      return { status: 204, body: "" };
    });
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
        url: `http://origin.example:${port}/deep/path?a=b`,
        method: "GET",
        headers: { host: "origin.example" },
      });
      await readBody(response.body);

      expect(response.status).toBe(204);
      expect(seenPath).toBe("/deep/path?a=b");
      expect(seenHost).toBe("origin.example");
    } finally {
      ports.close(connection.id);
    }
  });

  /**
   * The adapter half of the response-header budget (`LINK-vwnccgxf`).
   *
   * `maxHeaderSize` is an option on the real `http.request` call, so nothing in
   * the fixture suite can exercise it. Before the budget existed an oversized
   * head still failed — Node's default `--max-http-header-size` caught it — but
   * `HPE_HEADER_OVERFLOW` is neither ECONNRESET/EPIPE nor ETIMEDOUT, so it fell
   * through to the raw error and surfaced as the generic `http-error`,
   * indistinguishable from a socket fault.
   */
  it("refuses an oversized response head with a header-budget cause, not a socket fault", async () => {
    const port = await startServer(() => ({
      status: 200,
      body: "unreachable",
      headers: { "x-pad": "p".repeat(2_000) },
    }));
    // Set well below the 2 KB head the server sends AND below Node's 16 KB
    // default, so a pass proves this bound was applied rather than the runtime's.
    const ports = new NodeConnectionPorts(512);

    const connection = await ports.connect({
      protocol: "http:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
    });

    try {
      const failure = await ports.request({
        connectionId: connection.id,
        url: `http://origin.example:${port}/big`,
        method: "GET",
        headers: { host: "origin.example" },
      }).then(
        () => null,
        (error: unknown) => error,
      );

      expect(failure).not.toBeNull();
      expect((failure as { code?: unknown }).code).toBe("response-headers-too-large");
    } finally {
      ports.close(connection.id);
    }
  });

  it("accepts a head that fits the configured budget", async () => {
    // Guards against a vacuous pass above: the same server shape, under a budget
    // the head fits, must still complete.
    const port = await startServer(() => ({
      status: 200,
      body: "ok",
      headers: { "x-pad": "p".repeat(2_000) },
    }));
    const ports = new NodeConnectionPorts(8_192);

    const connection = await ports.connect({
      protocol: "http:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
    });

    try {
      const response = await ports.request({
        connectionId: connection.id,
        url: `http://origin.example:${port}/big`,
        method: "GET",
        headers: { host: "origin.example" },
      });
      expect(response.status).toBe(200);
      expect(await readBody(response.body)).toBe("ok");
    } finally {
      ports.close(connection.id);
    }
  });
});

/**
 * `docs/safe-transport.md` states the built-in transport has no proxy, and F10
 * in `docs/guarantees.md` is the register row these tests pin.
 *
 * The property is not an accident of configuration: `openSocket` calls
 * `net.connect` / `tls.connect` directly, and `request()` hangs the pinned
 * socket off a freshly constructed `http.Agent` that was never handed a
 * `proxyEnv`. Both switches below are aimed at a dead loopback sentinel, so a
 * transport that started honouring them would fail with `ECONNREFUSED` rather
 * than degrade quietly.
 */
describe("node transport ports — ambient proxy isolation (live loopback)", () => {
  it.skipIf(!RUNTIME_GLOBAL_PROXY_SUPPORTED)(
    "stays direct while a runtime global proxy points at a dead sentinel",
    async () => {
      const proxyPort = await deadLoopbackPort();
      const port = await startServer(() => ({ status: 200, body: "direct" }));

      await withRuntimeGlobalProxy(proxyPort, async () => {
        // Control first. Without this the test could pass because the proxy was
        // never installed, which is the failure mode that makes an isolation
        // test worthless.
        expect(await globalAgentIsProxied()).toBe(true);

        const ports = new NodeConnectionPorts();
        const connection = await ports.connect({
          protocol: "http:",
          hostname: "origin.example",
          address: "127.0.0.1",
          port,
        });
        try {
          // The observed peer is the destination. Had the socket been tunnelled
          // it would name the proxy instead — and with a dead sentinel there
          // would be no socket at all.
          expect(connection.remoteAddress).toBe("127.0.0.1");
          expect(connection.remotePort).toBe(port);
          expect(connection.remotePort).not.toBe(proxyPort);

          const response = await ports.request({
            connectionId: connection.id,
            url: `http://origin.example:${port}/probe`,
            method: "GET",
            headers: { host: "origin.example" },
          });
          expect(response.status).toBe(200);
          expect(await readBody(response.body)).toBe("direct");
        } finally {
          ports.close(connection.id);
        }
      });
    },
  );

  it("stays direct in a process started under NODE_USE_ENV_PROXY", async () => {
    const proxyPort = await deadLoopbackPort();
    const port = await startServer(() => ({ status: 200, body: "direct hello" }));

    const report = await runUnderStartupProxyEnv("http:", port, proxyPort);

    // Control: the child really was launched into an active ambient proxy, and
    // it was *this* sentinel that swallowed the default global agent.
    expect(report.control.proxied).toBe(true);
    expect(report.control.code).toBe("ECONNREFUSED");
    expect(report.control.port).toBe(proxyPort);

    expect(report.direct.status).toBe(200);
    expect(report.direct.body).toBe("direct hello");
    expect(report.direct.remoteAddress).toBe("127.0.0.1");
    expect(report.direct.remotePort).toBe(port);
  }, 30_000);
});

/**
 * LINK-syeupoav — response decoding against a real server, not a fixture port.
 *
 * The decoder had fixture-port coverage only, and every fixture supplied a
 * NON-EMPTY body. Nothing in the suite had ever put a real HEAD, 204 or empty
 * 200 from a compressing origin through the real HTTP/1.1 parser, so the shape
 * that breaks the decoder was the one shape never tested.
 *
 * These drive `NodeConnectionPorts` directly and call `decodeResponseBody` on
 * what actually came off the socket. They stop at the ports layer on purpose:
 * `SafeTransport` pins the destination through `classifyTransportAddress`,
 * which correctly refuses loopback, and its post-connect check compares the
 * OBSERVED peer against that pin (LINK-abozdqtp). Faking either to host a
 * decompression test would disarm a live security guard for an unrelated
 * assertion, so the transport-level outcome and budget assertions live in
 * `safe-transport.test.ts` over the fixture ports instead. Between them the two
 * halves cover the path end to end without either one lying.
 */
describe("node transport response decoding (live loopback)", () => {
  async function fetchRaw(
    port: number,
    method: "GET" | "HEAD",
    path = "/",
  ): Promise<{ status: number; headers: Readonly<Record<string, readonly string[]>>; bytes: Uint8Array }> {
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
        url: `http://origin.example:${port}${path}`,
        method,
        headers: { host: "origin.example" },
      });
      return {
        status: response.status,
        headers: response.headers,
        bytes: await readBodyBytes(response.body),
      };
    } finally {
      ports.close(connection.id);
    }
  }

  const PAYLOAD = "<html><body>hello</body></html>";

  /**
   * RFC 9110 9.3.2: a HEAD response carries the header fields it would send for
   * a GET, `Content-Encoding` included, with no body. nginx, Apache and
   * Cloudflare all comply, so this is the shape a real compressing origin
   * returns — and the shape the transport used to report as
   * `decompression-error`.
   */
  it("decodes a HEAD response against a gzip resource to an empty body", async () => {
    const compressed = gzipSync(PAYLOAD);
    const port = await startServer(() => ({
      status: 200,
      body: compressed,
      headers: {
        "content-encoding": "gzip",
        "content-type": "text/html",
        "content-length": String(compressed.byteLength),
      },
    }));

    const { status, headers, bytes } = await fetchRaw(port, "HEAD");

    // The server really did advertise the encoding, so the case is not vacuous.
    expect(status).toBe(200);
    expect(headers["content-encoding"]).toEqual(["gzip"]);
    expect(bytes.byteLength).toBe(0);
    expect(decodeResponseBody(bytes, headers, 1_000_000).byteLength).toBe(0);
  });

  it("decodes a 204 carrying a gzip encoding to an empty body", async () => {
    const port = await startServer(() => ({
      status: 204,
      body: "",
      headers: { "content-encoding": "gzip" },
    }));

    const { status, headers, bytes } = await fetchRaw(port, "GET");

    expect(status).toBe(204);
    expect(headers["content-encoding"]).toEqual(["gzip"]);
    expect(bytes.byteLength).toBe(0);
    expect(decodeResponseBody(bytes, headers, 1_000_000).byteLength).toBe(0);
  });

  it("decodes an empty 200 carrying a gzip encoding to an empty body", async () => {
    const port = await startServer(() => ({
      status: 200,
      body: "",
      headers: { "content-encoding": "gzip", "content-length": "0" },
    }));

    const { status, headers, bytes } = await fetchRaw(port, "GET");

    expect(status).toBe(200);
    expect(headers["content-encoding"]).toEqual(["gzip"]);
    expect(bytes.byteLength).toBe(0);
    expect(decodeResponseBody(bytes, headers, 1_000_000).byteLength).toBe(0);
  });

  /**
   * The compressed round trip existed only over the fixture port, where the
   * bytes are handed straight to the decoder. Here they cross a real socket and
   * the real HTTP/1.1 parser first, which is what makes the empty cases above
   * meaningful: the same path carries a real body correctly.
   */
  it.each([
    { encoding: "gzip", compress: gzipSync },
    { encoding: "deflate", compress: deflateSync },
    { encoding: "br", compress: brotliCompressSync },
  ])("round-trips a $encoding body over a real socket", async ({ encoding, compress }) => {
    const compressed = compress(PAYLOAD);
    const port = await startServer(() => ({
      status: 200,
      body: compressed,
      headers: { "content-encoding": encoding, "content-type": "text/html" },
    }));

    const { headers, bytes } = await fetchRaw(port, "GET");

    expect(bytes.byteLength).toBeGreaterThan(0);
    expect(Buffer.from(decodeResponseBody(bytes, headers, 1_000_000)).toString("utf8"))
      .toBe(PAYLOAD);
  });
});
