/**
 * Live coverage for the https branch of `openSocket` in `transport/node.ts`.
 *
 * `LINK-gqqrwrpk` proved the concrete Node paths can be fully broken while the
 * suite is green, because every other transport test injects the fixture
 * harness. PR #128 closed that gap for plain HTTP only; the TLS branch —
 * `connectTls`, ALPN, SNI, `rejectUnauthorized` and the identity re-check —
 * still had no behavioral coverage (LINK-cubfsqmr).
 *
 * The CA is injected with `tls.setDefaultCACertificates()` rather than by
 * weakening `rejectUnauthorized`. That matters: a test that disables
 * verification cannot claim to cover verification. The production code is
 * exercised exactly as it ships, with the fixture CA temporarily trusted at the
 * process level and restored afterwards.
 *
 * Loopback only — no external network.
 */
import { readFileSync } from "node:fs";
import { createServer as createTlsServer, type Server as TlsServer } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { dirname, join } from "node:path";
import { getCACertificates, setDefaultCACertificates, type TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { NodeConnectionPorts } from "../src/transport/node.js";
import {
  RUNTIME_GLOBAL_PROXY_SUPPORTED,
  deadLoopbackPort,
  globalAgentIsProxied,
  runUnderStartupProxyEnv,
  withRuntimeGlobalProxy,
} from "./proxy-isolation-harness.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "tls");
const pem = (name: string) => readFileSync(join(FIXTURES, name), "utf8");

const CA = pem("ca.cert.pem");

interface Identity {
  readonly key: string;
  readonly cert: string;
}
const identity = (prefix: string): Identity => ({
  key: pem(`${prefix}.key.pem`),
  cert: pem(`${prefix}.cert.pem`),
});

let originalCAs: readonly string[] | undefined;

beforeAll(() => {
  // getCACertificates("default") is what tls.connect consults when no explicit
  // `ca` is passed, which is exactly the production call shape.
  originalCAs = getCACertificates("default");
  setDefaultCACertificates([...originalCAs, CA]);
});

afterAll(() => {
  if (originalCAs !== undefined) setDefaultCACertificates([...originalCAs]);
});

let server: TlsServer | undefined;

afterEach(async () => {
  const running = server;
  server = undefined;
  if (running === undefined) return;
  // close() alone waits for lingering sockets; a half-closed handshake attempt
  // can keep it pending until the test times out.
  running.closeAllConnections();
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

interface Started {
  readonly port: number;
  /** Server-side view of the handshake, for SNI/ALPN assertions. */
  readonly seen: { servername?: string | undefined; alpnProtocol?: string | false | null };
}

async function startTlsServer(id: Identity, body = "secure hello"): Promise<Started> {
  const seen: Started["seen"] = {};
  const created = createTlsServer(
    {
      key: id.key,
      cert: id.cert,
      ALPNProtocols: ["http/1.1"],
      // Observed through SNICallback rather than the `secureConnection` event:
      // the event races the client's own `secureConnect`, so a test that reads
      // it can pass or fail depending on which side wins. SNICallback fires
      // during the handshake, on the ClientHello, and is therefore ordered.
      // It is simply not called when the client sends no SNI, which is what the
      // IP-literal case asserts.
      SNICallback: (servername, callback) => {
        seen.servername = servername;
        // A null context selects the server's default key/cert pair.
        callback(null);
      },
    },
    (req, res) => {
      seen.alpnProtocol = (req.socket as TLSSocket).alpnProtocol;
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(body);
    },
  );
  // A rejected handshake surfaces here; swallow it so it is not an unhandled
  // error event while the client assertion runs.
  created.on("tlsClientError", () => undefined);
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return { port: address.port, seen };
}

async function readBody(body: AsyncIterable<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/** Capture the transport's cause code for a connect that is expected to fail. */
async function connectFailure(
  ports: NodeConnectionPorts,
  request: Parameters<NodeConnectionPorts["connect"]>[0],
): Promise<string> {
  try {
    const connection = await ports.connect(request);
    ports.close(connection.id);
    throw new Error("expected connect to fail");
  } catch (error) {
    if (error instanceof Error && error.name === "NodePortFailure") {
      return (error as Error & { code: string }).code;
    }
    throw error;
  }
}

describe("node TLS transport (live loopback)", () => {
  it("completes a verified handshake and reports the peer identity", async () => {
    const { port, seen } = await startTlsServer(identity("valid"));
    const ports = new NodeConnectionPorts();

    const connection = await ports.connect({
      protocol: "https:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
    });

    try {
      expect(connection.tls?.authorized).toBe(true);
      expect(connection.tls?.serverName).toBe("origin.example");
      expect(connection.tls?.peerDnsNames).toEqual(["origin.example"]);
      expect(connection.remoteAddress).toBe("127.0.0.1");
      // Both peer fields come off the socket. The adapter has no fallback to the
      // requested address/port to fill them in with (LINK-abozdqtp).
      expect(connection.remotePort).toBe(port);
      // SNI is sent for a DNS name even though the socket is pinned to a
      // literal address.
      expect(seen.servername).toBe("origin.example");
    } finally {
      ports.close(connection.id);
    }
  });

  it("speaks HTTP/1.1 over the pinned TLS socket", async () => {
    const { port, seen } = await startTlsServer(identity("valid"), "over tls");
    const ports = new NodeConnectionPorts();

    const connection = await ports.connect({
      protocol: "https:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
    });

    try {
      const response = await ports.request({
        connectionId: connection.id,
        url: `https://origin.example:${port}/probe?q=1`,
        method: "GET",
        headers: { host: "origin.example" },
      });
      expect(response.status).toBe(200);
      expect(await readBody(response.body)).toBe("over tls");
      // ALPN is constrained to HTTP/1.1, read from the socket the request
      // actually arrived on.
      expect(seen.alpnProtocol).toBe("http/1.1");
    } finally {
      ports.close(connection.id);
    }
  });

  it("does not send SNI when the identity is an IP literal", async () => {
    const { port, seen } = await startTlsServer(identity("valid"));
    const ports = new NodeConnectionPorts();

    // An IP identity cannot match the leaf, so the handshake is expected to
    // fail; the point of the assertion is that no SNI was offered.
    await connectFailure(ports, {
      protocol: "https:",
      hostname: "127.0.0.1",
      address: "127.0.0.1",
      port,
    });
    expect(seen.servername).toBeUndefined();
  });

  it("maps an untrusted self-signed chain to tls-certificate", async () => {
    const { port } = await startTlsServer(identity("untrusted"));
    const ports = new NodeConnectionPorts();

    expect(
      await connectFailure(ports, {
        protocol: "https:",
        hostname: "origin.example",
        address: "127.0.0.1",
        port,
      }),
    ).toBe("tls-certificate");
  });

  it("maps an expired certificate to tls-certificate", async () => {
    const { port } = await startTlsServer(identity("expired"));
    const ports = new NodeConnectionPorts();

    expect(
      await connectFailure(ports, {
        protocol: "https:",
        hostname: "origin.example",
        address: "127.0.0.1",
        port,
      }),
    ).toBe("tls-certificate");
  });

  it("maps a correctly signed certificate for the wrong name to tls-certificate", async () => {
    // Chain verification passes — the CA is trusted and the cert is in date.
    // Only the name is wrong, so this is the identity check failing rather than
    // the chain, which is the case a CA-only test would miss.
    const { port } = await startTlsServer(identity("wrong-name"));
    const ports = new NodeConnectionPorts();

    expect(
      await connectFailure(ports, {
        protocol: "https:",
        hostname: "origin.example",
        address: "127.0.0.1",
        port,
      }),
    ).toBe("tls-certificate");
  });

  it("honours serverName over hostname when selecting the identity to verify", async () => {
    const { port, seen } = await startTlsServer(identity("wrong-name"));
    const ports = new NodeConnectionPorts();

    const connection = await ports.connect({
      protocol: "https:",
      hostname: "origin.example",
      address: "127.0.0.1",
      port,
      serverName: "other.example",
    });

    try {
      expect(connection.tls?.authorized).toBe(true);
      expect(connection.tls?.serverName).toBe("other.example");
      expect(seen.servername).toBe("other.example");
    } finally {
      ports.close(connection.id);
    }
  });

  // --- identity vs. pin (LINK-bgcfgujq) ------------------------------------
  //
  // `openSocket` connects to `request.address` — the pinned answer — but must
  // verify `request.serverName ?? request.hostname`. Node's own default would
  // verify `options.servername || options.host`, and `options.host` IS the pin.
  // The pair below is the input that tells those two rules apart: without the
  // `checkServerIdentity` override in `openSocket`, the second case AUTHORIZES.
  //
  // The certificate attests `IP:127.0.0.1` and no DNS name, so it is genuinely
  // valid for the address the socket reaches and says nothing about the name
  // the caller asked for.

  it("accepts a leaf that attests the requested IP identity", async () => {
    // Positive control for the pair. It proves the IP-SAN path verifies at all,
    // so the rejection below is about WHICH name was checked rather than about
    // IP SANs being unsupported. On Node >= 26 it also proves the
    // `isIP(identity) === 0` guard is doing its job: setting `servername` to an
    // IP literal throws ERR_INVALID_ARG_VALUE there (it merely warned, DEP0123,
    // on Node 24), so dropping the guard fails this case synchronously.
    const { port, seen } = await startTlsServer(identity("ip-san"));
    const ports = new NodeConnectionPorts();

    const connection = await ports.connect({
      protocol: "https:",
      hostname: "127.0.0.1",
      address: "127.0.0.1",
      port,
    });

    try {
      expect(connection.tls?.authorized).toBe(true);
      expect(connection.tls?.serverName).toBe("127.0.0.1");
      // No DNS SAN at all — the leaf attests an address and nothing else.
      expect(connection.tls?.peerDnsNames).toEqual([]);
      // RFC 6066 forbids an IP literal in SNI, so none was offered.
      expect(seen.servername).toBeUndefined();
    } finally {
      ports.close(connection.id);
    }
  });

  it("rejects a leaf that attests the pinned address but not the requested identity", async () => {
    // The pin (`address`) and the identity (`hostname`) are independent inputs
    // at this port's contract — that independence is the whole point of DNS
    // pinning. The leaf is valid for 127.0.0.1, which is where the socket
    // actually goes, but the caller asked for 10.0.0.1 and the leaf says
    // nothing about that name.
    //
    // Node's default would compare the certificate against `options.host` —
    // i.e. against the pin — and authorize, letting the pinned address confirm
    // itself. That is the TLS-layer form of the failure LINK-abozdqtp names for
    // the peer-address check.
    const { port } = await startTlsServer(identity("ip-san"));
    const ports = new NodeConnectionPorts();

    expect(
      await connectFailure(ports, {
        protocol: "https:",
        hostname: "10.0.0.1",
        address: "127.0.0.1",
        port,
      }),
    ).toBe("tls-certificate");
  });

  it("maps a refused TLS connection to connect-refused", async () => {
    // Bind and release a port so nothing is listening on a known-free number.
    const probe = createTcpServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    const address = probe.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    const closedPort = address.port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));

    const ports = new NodeConnectionPorts();
    expect(
      await connectFailure(ports, {
        protocol: "https:",
        hostname: "origin.example",
        address: "127.0.0.1",
        port: closedPort,
      }),
    ).toBe("connect-refused");
  });

  it("maps a non-TLS listener to tls-handshake rather than a certificate fault", async () => {
    // Distinguishing "the peer is not speaking TLS" from "the peer's identity
    // is wrong" matters: only the latter is evidence about the destination.
    // net.Server has no closeAllConnections(), so the accepted socket is
    // tracked by hand — close() would otherwise block on it until the timeout.
    const accepted: import("node:net").Socket[] = [];
    const plain = createTcpServer((socket) => {
      accepted.push(socket);
      socket.on("error", () => undefined);
      socket.end("not tls\r\n");
    });
    await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", () => resolve()));
    const address = plain.address();
    if (address === null || typeof address === "string") throw new Error("no port");

    const ports = new NodeConnectionPorts();
    try {
      expect(
        await connectFailure(ports, {
          protocol: "https:",
          hostname: "origin.example",
          address: "127.0.0.1",
          port: address.port,
        }),
      ).toBe("tls-handshake");
    } finally {
      for (const socket of accepted) socket.destroy();
      await new Promise<void>((resolve) => plain.close(() => resolve()));
    }
  });
});

/**
 * The HTTPS half of the ambient-proxy isolation regression (`LINK-xscdzrji`,
 * register row F10). It is a separate case from the HTTP one on purpose:
 * `HTTPS_PROXY` is the variable that would apply here, and a proxied HTTPS
 * client tunnels with `CONNECT` rather than rewriting the request target — a
 * different code path in Node from the plain-HTTP one.
 *
 * `openSocket` reaches `tls.connect` directly, so there is nothing for either
 * switch to attach to. Both cases aim at a dead loopback sentinel, so a
 * regression here is an `ECONNREFUSED`, not a slow test.
 *
 * Scope: the *built-in* adapters only. A caller that supplies its own connector
 * or HTTP port owns whatever proxy behavior that adapter has, which is why
 * `docs/safe-transport.md` states the limit rather than leaving it implied.
 */
describe("node TLS transport — ambient proxy isolation (live loopback)", () => {
  it.skipIf(!RUNTIME_GLOBAL_PROXY_SUPPORTED)(
    "completes a verified handshake while a runtime global proxy points at a dead sentinel",
    async () => {
      const proxyPort = await deadLoopbackPort();
      const { port, seen } = await startTlsServer(identity("valid"), "direct over tls");

      await withRuntimeGlobalProxy(proxyPort, async () => {
        // Control: the ambient proxy really is installed in this process.
        expect(await globalAgentIsProxied()).toBe(true);

        const ports = new NodeConnectionPorts();
        const connection = await ports.connect({
          protocol: "https:",
          hostname: "origin.example",
          address: "127.0.0.1",
          port,
        });
        try {
          expect(connection.tls?.authorized).toBe(true);
          expect(connection.remoteAddress).toBe("127.0.0.1");
          expect(connection.remotePort).toBe(port);
          expect(connection.remotePort).not.toBe(proxyPort);
          // SNI reached the origin itself, not a tunnel endpoint.
          expect(seen.servername).toBe("origin.example");

          const response = await ports.request({
            connectionId: connection.id,
            url: `https://origin.example:${port}/probe`,
            method: "GET",
            headers: { host: "origin.example" },
          });
          expect(response.status).toBe(200);
          expect(await readBody(response.body)).toBe("direct over tls");
        } finally {
          ports.close(connection.id);
        }
      });
    },
  );

  it("completes a verified handshake in a process started under NODE_USE_ENV_PROXY", async () => {
    const proxyPort = await deadLoopbackPort();
    const { port } = await startTlsServer(identity("valid"), "direct over tls");

    const report = await runUnderStartupProxyEnv("https:", port, proxyPort);

    // Control: the child really was launched into an active ambient proxy.
    expect(report.control.proxied).toBe(true);
    expect(report.control.code).toBe("ECONNREFUSED");
    expect(report.control.port).toBe(proxyPort);

    expect(report.direct.status).toBe(200);
    expect(report.direct.body).toBe("direct over tls");
    expect(report.direct.remoteAddress).toBe("127.0.0.1");
    expect(report.direct.remotePort).toBe(port);
  }, 30_000);
});
