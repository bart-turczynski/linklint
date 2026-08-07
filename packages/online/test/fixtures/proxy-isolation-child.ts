/**
 * Child half of the ambient-proxy isolation regression (`LINK-xscdzrji`).
 *
 * `NODE_USE_ENV_PROXY` is read once, while the `http`/`https` global agents are
 * built during bootstrap. Setting it from inside a running test does nothing —
 * verified on Node 26.3.1 — so the startup case can only be exercised in a
 * process that was *launched* with it. This script is that process: the parent
 * test spawns it with `NODE_USE_ENV_PROXY=1` and hostile `HTTP_PROXY` /
 * `HTTPS_PROXY` / `ALL_PROXY` values aimed at a dead loopback sentinel, then
 * reads the JSON report from stdout.
 *
 * The report carries two things:
 *
 *   - `control` — proof the ambient proxy really is live in *this* process. A
 *     request on the default global agent, naming a loopback server this script
 *     started itself, must fail against the sentinel's address and port. If
 *     Node ever stops honouring the variable, this goes quiet and the parent
 *     fails rather than passing vacuously.
 *   - `direct` — what the production `NodeConnectionPorts` path observed. The
 *     peer address and port are read back so the parent can assert the socket
 *     landed on the destination and not on the proxy.
 *
 * Usage: `node --import tsx proxy-isolation-child.ts <protocol> <port>`.
 */
import { readFileSync } from "node:fs";
import { createServer, request as nodeHttpRequest, type Server } from "node:http";
import { dirname, join } from "node:path";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { fileURLToPath } from "node:url";

import { NodeConnectionPorts } from "../../src/transport/node.js";

interface ControlReport {
  /** `true` when the global-agent request never reached the named server. */
  readonly proxied: boolean;
  readonly code?: string;
  readonly address?: string;
  readonly port?: number;
}

const HERE = dirname(fileURLToPath(import.meta.url));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

/**
 * Ask the *default* global agent for a loopback server started here. Under an
 * active ambient proxy the request is tunnelled to the sentinel instead and
 * dies there; with no proxy in effect it simply succeeds.
 */
async function probeGlobalAgent(): Promise<ControlReport> {
  const server = createServer((_request, response) => response.end("control"));
  const port = await listen(server);
  try {
    return await new Promise<ControlReport>((resolve) => {
      const request = nodeHttpRequest({ host: "127.0.0.1", port, path: "/" }, (response) => {
        response.resume();
        response.on("end", () => resolve({ proxied: false }));
      });
      request.on("error", (error: Error) => {
        // `address` / `port` are present on a connection error but absent from
        // the `ErrnoException` declaration, so they are read through a narrowed
        // view. They are what lets the parent assert the *sentinel* swallowed
        // the request rather than some unrelated failure.
        const failure = error as Error & {
          code?: unknown;
          address?: unknown;
          port?: unknown;
        };
        resolve({
          proxied: true,
          ...(typeof failure.code === "string" ? { code: failure.code } : {}),
          ...(typeof failure.address === "string" ? { address: failure.address } : {}),
          ...(typeof failure.port === "number" ? { port: failure.port } : {}),
        });
      });
      request.end();
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function readBody(body: AsyncIterable<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  const protocol = process.argv[2];
  const port = Number(process.argv[3]);
  if (protocol !== "http:" && protocol !== "https:") throw new Error("bad protocol argument");
  if (!Number.isInteger(port)) throw new Error("bad port argument");

  const control = await probeGlobalAgent();

  if (protocol === "https:") {
    // Same shape as the TLS live suite: trust the fixture CA at the process
    // level rather than weakening `rejectUnauthorized` in production code.
    const ca = readFileSync(join(HERE, "tls", "ca.cert.pem"), "utf8");
    setDefaultCACertificates([...getCACertificates("default"), ca]);
  }

  const ports = new NodeConnectionPorts();
  const connection = await ports.connect({
    protocol,
    hostname: "origin.example",
    address: "127.0.0.1",
    port,
  });
  try {
    const response = await ports.request({
      connectionId: connection.id,
      url: `${protocol}//origin.example:${port}/probe`,
      method: "GET",
      headers: { host: "origin.example" },
    });
    const body = await readBody(response.body);
    process.stdout.write(
      JSON.stringify({
        control,
        direct: {
          status: response.status,
          body,
          remoteAddress: connection.remoteAddress,
          remotePort: connection.remotePort,
        },
      }),
    );
  } finally {
    ports.close(connection.id);
  }
}

await main();
