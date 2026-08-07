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
import { afterEach, describe, expect, it } from "vitest";

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
    body: string;
  },
): Promise<number> {
  const created = createServer((req, res) => {
    const { status, body } = handler(req.url ?? "/", req.headers);
    res.writeHead(status, { "content-type": "text/plain" });
    res.end(body);
  });
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

async function readBody(body: AsyncIterable<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
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
