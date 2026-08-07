import {
  Agent as NodeHttpAgent,
  request as nodeHttpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
} from "node:http";
import {
  connect as connectTcp,
  isIP,
  type Socket,
} from "node:net";
import {
  checkServerIdentity,
  connect as connectTls,
  type PeerCertificate,
  type TLSSocket,
} from "node:tls";

import { NodeResolver, systemErrorCode } from "./node-resolver.js";
import { observedPeer } from "./peer.js";
import { createSafeTransport } from "./safe-transport.js";
import { SystemClock } from "./system-clock.js";
import {
  DEFAULT_TRANSPORT_POLICY,
  resolveTransportPolicy,
  type TransportPolicy,
} from "./policy.js";
import type {
  ConnectRequest,
  ConnectorPort,
  HttpPort,
  HttpRequest,
  HttpResponse,
  ResolverPort,
  SafeTransport,
  TransportConnection,
  TransportCauseCode,
} from "./types.js";

class NodePortFailure extends Error {
  constructor(readonly code: TransportCauseCode) {
    super("node transport operation failed");
    this.name = "NodePortFailure";
  }
}

class NodeAbortError extends Error {
  constructor() {
    super("node transport operation aborted");
    this.name = "AbortError";
  }
}

/**
 * One-shot pinned sockets shared by the connector and HTTP/1.1 port.
 *
 * Internal to this module — deliberately absent from the public `./transport`
 * export map. Exported only so the live loopback regression test can exercise
 * the real socket and HTTP/1.1 wiring, which every fixture-based test bypasses.
 */
export class NodeConnectionPorts implements ConnectorPort, HttpPort {
  private nextConnectionId = 1;
  private readonly sockets = new Map<string, Socket | TLSSocket>();

  /**
   * @param maxResponseHeaderBytes Handed to the response parser as
   * `maxHeaderSize`, so an oversized head is refused while it is still coming
   * off the socket. Defaults to the policy default, which is also Node's own
   * `--max-http-header-size`, so a bare construction behaves as before.
   */
  constructor(
    private readonly maxResponseHeaderBytes: number =
      DEFAULT_TRANSPORT_POLICY.maxResponseHeaderBytes,
  ) {}

  async connect(request: ConnectRequest): Promise<TransportConnection> {
    const socket = await this.openSocket(request);
    // Report the OBSERVED peer or nothing. Falling back to `request.address` /
    // `request.port` here would hand the caller its own pin back and let the
    // address check confirm itself (LINK-abozdqtp).
    const peer = observedPeer(socket);
    if (peer === null) {
      socket.destroy();
      throw new NodePortFailure("connect-error");
    }
    const id = `node-${this.nextConnectionId++}`;
    this.sockets.set(id, socket);
    const base = {
      id,
      protocol: request.protocol,
      remoteAddress: peer.address,
      remotePort: peer.port,
    } as const;
    if (request.protocol === "http:") return base;

    const tlsSocket = socket as TLSSocket;
    return {
      ...base,
      tls: {
        authorized: tlsSocket.authorized,
        serverName: request.serverName ?? request.hostname,
        peerDnsNames: peerDnsNames(tlsSocket.getPeerCertificate()),
      },
    };
  }

  close(connectionId: string): void {
    const socket = this.sockets.get(connectionId);
    this.sockets.delete(connectionId);
    socket?.destroy();
  }

  async request(request: HttpRequest): Promise<HttpResponse> {
    const socket = this.sockets.get(request.connectionId);
    if (!socket) throw new NodePortFailure("http-reset");
    const url = new URL(request.url);

    // `createConnection` must hang off an explicit Agent. Passing it alongside
    // `agent: false` is silently ignored, and the unresolvable placeholder host
    // then reaches getaddrinfo — every request fails with ENOTFOUND before the
    // pinned socket is ever used.
    const agent = new NodeHttpAgent({ keepAlive: false });
    agent.createConnection = () => socket;

    return new Promise<HttpResponse>((resolve, reject) => {
      let settled = false;
      const clientRequest = nodeHttpRequest(
        {
          method: request.method,
          host: "pinned.invalid",
          port: 80,
          path: `${url.pathname}${url.search}`,
          headers: request.headers,
          agent,
          // The tight seam for the header-byte budget: llhttp stops parsing at
          // this bound, so an oversized head never finishes being buffered.
          // Node applies its own `--max-http-header-size` when this is absent,
          // which is a runtime-dependent cap this boundary would be inheriting
          // rather than stating.
          maxHeaderSize: this.maxResponseHeaderBytes,
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        },
        (response: IncomingMessage) => {
          settled = true;
          resolve({
            status: response.statusCode ?? 0,
            headers: responseHeaders(response.headers),
            body: response,
          });
        },
      );
      clientRequest.once("error", (error) => {
        if (settled) return;
        const code = systemErrorCode(error);
        if (code === "ECONNRESET" || code === "EPIPE") {
          reject(new NodePortFailure("http-reset"));
        } else if (code === "ETIMEDOUT") {
          reject(new NodePortFailure("http-timeout"));
        } else if (code === "HPE_HEADER_OVERFLOW") {
          // Without this the budget still stops the response, but reports as the
          // generic `http-error` — indistinguishable from a socket fault, and so
          // useless as evidence that a policy limit is what refused the head.
          reject(new NodePortFailure("response-headers-too-large"));
        } else {
          reject(error);
        }
      });
      clientRequest.end();
    });
  }

  private openSocket(request: ConnectRequest): Promise<Socket | TLSSocket> {
    return new Promise((resolve, reject) => {
      let socket: Socket | TLSSocket;
      let settled = false;
      const identity = request.serverName ?? request.hostname;
      const onError = (error: Error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        const code = systemErrorCode(error);
        if (request.signal?.aborted) reject(new NodeAbortError());
        else if (code === "ECONNREFUSED") reject(new NodePortFailure("connect-refused"));
        else if (code === "ETIMEDOUT") reject(new NodePortFailure("connect-timeout"));
        else if (request.protocol === "https:" && isCertificateError(code)) {
          reject(new NodePortFailure("tls-certificate"));
        } else if (request.protocol === "https:") {
          reject(new NodePortFailure("tls-handshake"));
        } else reject(error);
      };
      const onConnected = () => {
        if (settled) return;
        if (request.protocol === "https:") {
          const tlsSocket = socket as TLSSocket;
          const identityError = tlsSocket.authorized
            ? checkServerIdentity(identity, tlsSocket.getPeerCertificate())
            : new Error("TLS peer is not authorized");
          if (identityError) {
            settled = true;
            socket.removeListener("error", onError);
            socket.destroy();
            reject(new NodePortFailure("tls-certificate"));
            return;
          }
        }
        settled = true;
        socket.removeListener("error", onError);
        socket.on("error", ignoreSocketError);
        resolve(socket);
      };

      if (request.protocol === "https:") {
        socket = connectTls({
          host: request.address,
          port: request.port,
          rejectUnauthorized: true,
          ALPNProtocols: ["http/1.1"],
          checkServerIdentity: (_hostname, certificate) =>
            checkServerIdentity(identity, certificate),
          ...(isIP(identity) === 0 ? { servername: identity } : {}),
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        });
        socket.once("secureConnect", onConnected);
      } else {
        socket = connectTcp({
          host: request.address,
          port: request.port,
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        });
        socket.once("connect", onConnected);
      }
      socket.once("error", onError);
    });
  }
}

function ignoreSocketError(): void {
  // ClientRequest/IncomingMessage receive the same error. This guard covers the
  // short handoff between a completed connect and request listener attachment.
}

export interface CreateNodeSafeTransportOptions {
  readonly policy?: Partial<TransportPolicy>;
  readonly resolver?: ResolverPort;
}

/** Side-effect-free factory. Network activity begins only with an authorized fetch. */
export function createNodeSafeTransport(
  options: CreateNodeSafeTransportOptions = {},
): SafeTransport {
  // Resolved once here so the adapter's parser limit and the transport's own
  // re-measurement read the same number. `resolveTransportPolicy` is pure and
  // idempotent, so handing the resolved policy back to `createSafeTransport`
  // yields the same values it would have computed itself.
  const policy = resolveTransportPolicy(options.policy);
  const network = new NodeConnectionPorts(policy.maxResponseHeaderBytes);
  return createSafeTransport({
    resolver: options.resolver ?? new NodeResolver(),
    connector: network,
    http: network,
    clock: new SystemClock(),
    policy,
  });
}

function responseHeaders(
  headers: IncomingHttpHeaders,
): Readonly<Record<string, readonly string[]>> {
  const normalized: Record<string, readonly string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    normalized[name.toLowerCase()] = Array.isArray(value) ? [...value] : [String(value)];
  }
  return normalized;
}

function peerDnsNames(certificate: PeerCertificate): readonly string[] {
  const subjectAltName = certificate.subjectaltname;
  if (typeof subjectAltName !== "string") return [];
  return subjectAltName
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("DNS:"))
    .map((entry) => entry.slice(4));
}

function isCertificateError(code: string | null): boolean {
  return code !== null && (
    code.startsWith("ERR_TLS_CERT") ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID"
  );
}
