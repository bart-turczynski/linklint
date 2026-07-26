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
