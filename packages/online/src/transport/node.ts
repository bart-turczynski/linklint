import { lookup } from "node:dns/promises";
import {
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

import { createSafeTransport } from "./safe-transport.js";
import { SystemClock } from "./system-clock.js";
import type { TransportPolicy } from "./policy.js";
import type {
  ConnectRequest,
  ConnectorPort,
  DnsAddress,
  HttpPort,
  HttpRequest,
  HttpResponse,
  ResolveRequest,
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

class NodeResolver implements ResolverPort {
  async resolve(request: ResolveRequest): Promise<readonly DnsAddress[]> {
    try {
      const pending = lookup(request.hostname, { all: true, verbatim: true });
      const answers = await abortable(pending, request.signal);
      return answers.map((answer) => ({
        address: answer.address,
        family: answer.family === 6 ? 6 : 4,
        ttlSeconds: 0,
      }));
    } catch (error) {
      if (error instanceof NodeAbortError) throw error;
      const code = systemErrorCode(error);
      if (code === "ENOTFOUND" || code === "ENODATA") {
        throw new NodePortFailure("dns-not-found");
      }
      if (code === "EAI_AGAIN" || code === "ETIMEOUT") {
        throw new NodePortFailure("dns-timeout");
      }
      throw new NodePortFailure("dns-error");
    }
  }
}

/** One-shot pinned sockets shared by the connector and HTTP/1.1 port. */
class NodeConnectionPorts implements ConnectorPort, HttpPort {
  private nextConnectionId = 1;
  private readonly sockets = new Map<string, Socket | TLSSocket>();

  async connect(request: ConnectRequest): Promise<TransportConnection> {
    const socket = await this.openSocket(request);
    const id = `node-${this.nextConnectionId++}`;
    this.sockets.set(id, socket);
    const base = {
      id,
      protocol: request.protocol,
      remoteAddress: socket.remoteAddress ?? request.address,
      remotePort: socket.remotePort ?? request.port,
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

    return new Promise<HttpResponse>((resolve, reject) => {
      let settled = false;
      const clientRequest = nodeHttpRequest(
        {
          method: request.method,
          host: "pinned.invalid",
          port: 80,
          path: `${url.pathname}${url.search}`,
          headers: request.headers,
          agent: false,
          createConnection: () => socket,
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
  const network = new NodeConnectionPorts();
  return createSafeTransport({
    resolver: options.resolver ?? new NodeResolver(),
    connector: network,
    http: network,
    clock: new SystemClock(),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
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

function systemErrorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : null;
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

async function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) throw new NodeAbortError();
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new NodeAbortError());
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
    void promise.catch(() => undefined);
  }
}
