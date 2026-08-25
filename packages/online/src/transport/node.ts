import {
  Agent as NodeHttpAgent,
  request as nodeHttpRequest,
  type ClientRequest,
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
 * The characters Node refuses in a request header VALUE, transcribed from
 * `checkInvalidHeaderChar` in `lib/_http_common.js` (`headerCharRegex`,
 * byte-identical on both gated majors). Everything else — HTAB, printable
 * ASCII, and the whole `\x80`-`\xff` `obs-text` range — is sendable.
 *
 * DELIBERATELY NOT NARROWER. The wire line for a field value is Latin-1, not
 * ASCII: `accept-language: de-DE, fr;q=0.9` and any value carrying `ü` are
 * ordinary and must still reach the destination byte for byte. A guard drawn to
 * ASCII would refuse values a caller is entitled to send, which is a worse
 * defect than the untyped throw it would be fixing.
 *
 * `transport/headers.ts` screens the same values against `[\0\r\n]` before they
 * arrive here. That is a request-SPLITTING guard and it is PORT-AGNOSTIC — it
 * must hold for a caller-supplied HTTP port too, which is why it stays there
 * and is not folded into this one. This check answers a different question,
 * SENDABILITY, which is a property of the wire Node writes, so it belongs to
 * the adapter that writes it.
 */
const UNSENDABLE_HEADER_VALUE = /[^\t\x20-\x7e\x80-\xff]/;

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

    // Screened here rather than left to Node, even though the catch below would
    // also type it. Three reasons this is not the duplicated charset copy
    // `reputation/rdap-node.ts` declined:
    //
    //   1. These values are CALLER-supplied and free-form. RDAP's two are fixed
    //      literals whose only caller influence is a stored validator; here the
    //      public `SafeFetchRequest.headers` reaches the wire, so the boundary
    //      owes a stable answer about what it will and will not send.
    //   2. The copy is EXACT, not an approximation — see
    //      {@link UNSENDABLE_HEADER_VALUE} — and the catch stands behind it, so
    //      a future Node that refuses MORE than this pattern still lands on the
    //      same cause rather than escaping. Drift can only be narrow, and the
    //      Latin-1 control test is what holds that line.
    //   3. Two gated Node majors decide this. Answering it here makes the cause
    //      a property of this boundary rather than of whichever `ERR_*` code the
    //      host runtime happens to raise.
    //
    // The value is never quoted: `NodePortFailure` carries a code and nothing
    // else, and Node's own message (which names the field) is discarded.
    for (const value of Object.values(request.headers)) {
      if (UNSENDABLE_HEADER_VALUE.test(value)) throw new NodePortFailure("http-malformed");
    }

    return new Promise<HttpResponse>((resolve, reject) => {
      let settled = false;
      // Declared before the dispatch so the synchronous catch below can run
      // without one, and rejected through a single seam so the two failure
      // paths cannot settle twice or disagree. Nothing is destroyed here: on the
      // synchronous path no request object was ever built and the agent was
      // never asked for the socket, and on the asynchronous path Node has
      // already torn the request down before it emits `error`.
      let clientRequest: ClientRequest | undefined;
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      try {
        clientRequest = nodeHttpRequest(
          {
            method: request.method,
            host: "pinned.invalid",
            port: 80,
            path: `${url.pathname}${url.search}`,
            headers: request.headers,
            agent,
            // The tight seam for the header-byte budget: llhttp stops parsing
            // at this bound, so an oversized head never finishes being
            // buffered. Node applies its own `--max-http-header-size` when this
            // is absent, which is a runtime-dependent cap this boundary would
            // be inheriting rather than stating.
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
      } catch (error) {
        // `http.request` validates the option shape, the port and the whole
        // header block SYNCHRONOUSLY, inside the `ClientRequest` constructor, so
        // these throws happen before the request object exists and can never
        // reach the `error` listener attached below. Left bare, the executor
        // turned them into a rejection carrying a raw Node error — untyped at
        // this port, and reported one layer up as the generic `http-error`,
        // indistinguishable from a socket fault. Routed through the same mapper
        // as every asynchronous failure instead.
        fail(requestFailure(error));
        return;
      }
      clientRequest.once("error", (error) => fail(requestFailure(error)));
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
          // Second of the two identity checks. Today it can only ever agree with
          // the `checkServerIdentity` connect option below, because Node destroys
          // the socket before `secureConnect` whenever verification fails under
          // `rejectUnauthorized: true` — so `authorized` is always true here and
          // the certificate has not changed. It is kept rather than deleted
          // because its redundancy rests on a property of NODE, not of this file:
          // Node skips its own identity check on a resumed session
          // (`!this.isSessionReused()` in `internal/tls/wrap.js` `onConnectSecure`),
          // and this re-check has no such gate. `openSocket` never passes
          // `session`, so resumption is unreachable — but a future keep-alive or
          // session-cache change here would silently move the only surviving
          // check onto that gated path (LINK-bgcfgujq).
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

      // Both `net.connect` and `tls.connect` validate their options inside the
      // socket constructor and THROW rather than emitting `error`, so a refused
      // option escapes before `onError` is attached — the same bare-call shape
      // the header block had in `request` above.
      //
      // No caller path reaches it today: `port` comes from `effectivePort` on a
      // WHATWG-parsed URL and cannot be out of range, `address` is a classified
      // resolver answer, and the one known synchronous throw here — Node 26's
      // `ERR_INVALID_ARG_VALUE` for an IP `servername` — is explicitly guarded
      // below. That guard is exactly why the catch is not speculative: the
      // failure class has already materialized once in this call, on a gated
      // major, and was survived only because someone anticipated it. A boundary
      // that is typed only for the throws its authors enumerated is not typed.
      // `test/node-transport-headers.test.ts` drives it through the port
      // surface, where an out-of-range port IS reachable, so it is not dead.
      try {
        if (request.protocol === "https:") {
          socket = connectTls({
            host: request.address,
            port: request.port,
            rejectUnauthorized: true,
            ALPNProtocols: ["http/1.1"],
            // NOT redundant with Node's default, despite looking like it
            // (LINK-bgcfgujq, measured on Node 24.18 and 26.3 — the algorithm in
            // `tls.checkServerIdentity` is byte-identical on both).
            //
            // Node's default verifies `options.servername || options.host`, and
            // `options.host` is `request.address` — the PINNED answer. Whenever
            // `servername` is absent, which is exactly the IP-literal branch
            // below, Node would therefore check the certificate against the
            // address the socket reached instead of the identity the caller asked
            // for, letting the pin confirm itself. That is the TLS-layer form of
            // the failure LINK-abozdqtp names for the peer-address check.
            //
            // Passing `identity` explicitly pins the comparison to the requested
            // name on both branches and makes it independent of the `host` /
            // `servername` wiring. Those two happen to agree today only because
            // `safe-transport.ts` sets `serverName` to the hostname and `pin.ts`
            // passes IP literals through verbatim — an invariant held in two other
            // files, neither of which is obliged to keep holding it.
            //
            // Deleting this line alone leaves the suite green, because the
            // `secureConnect` re-check above covers the same ground; deleting BOTH
            // turns `node-transport-tls-live.test.ts`'s "rejects a leaf that
            // attests the pinned address but not the requested identity" red. The
            // two checks are redundant with EACH OTHER, not with Node.
            checkServerIdentity: (_hostname, certificate) =>
              checkServerIdentity(identity, certificate),
            // Omitted for an IP identity, and not merely to honour RFC 6066: Node
            // 26 THROWS `ERR_INVALID_ARG_VALUE` from `tls.connect` for an IP
            // `servername`, where Node 24 only warns (DEP0123). Both gated majors
            // are in the matrix, so this guard is load-bearing on one of them.
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
      } catch {
        // A local option Node refused: no socket exists to destroy, nothing was
        // sent, and no peer was contacted. `connect-error` is what the phase
        // would report anyway, stated here instead of inferred from an escaped
        // `RangeError`.
        settled = true;
        reject(new NodePortFailure("connect-error"));
        return;
      }
      socket.once("error", onError);
    });
  }
}

/**
 * Map one `node:http` client error onto the cause it represents.
 *
 * Reached from BOTH seams — the synchronous `ClientRequest` constructor throw
 * and the asynchronous `error` event — so a header block Node refuses cannot
 * report one cause on one path and another on the other.
 *
 * An unrecognized error is returned unchanged rather than flattened to a code.
 * `safe-transport.ts` already turns an unknown HTTP-phase rejection into
 * `http-error`, and swallowing the original here would only remove the detail a
 * debugger has left, without changing the outcome a caller sees.
 */
function requestFailure(error: unknown): unknown {
  const code = systemErrorCode(error);
  if (code === "ECONNRESET" || code === "EPIPE") return new NodePortFailure("http-reset");
  if (code === "ETIMEDOUT") return new NodePortFailure("http-timeout");
  if (code === "HPE_HEADER_OVERFLOW") {
    // Without this the budget still stops the response, but reports as the
    // generic `http-error` — indistinguishable from a socket fault, and so
    // useless as evidence that a policy limit is what refused the head.
    return new NodePortFailure("response-headers-too-large");
  }
  if (code === "ERR_INVALID_CHAR" || code === "ERR_INVALID_HTTP_TOKEN") {
    // Node's own verdict on the request header block, raised synchronously.
    // `UNSENDABLE_HEADER_VALUE` normally answers first; this is what keeps the
    // cause stable if Node ever refuses something that pattern admits — a name
    // that is not an RFC 9110 token included.
    return new NodePortFailure("http-malformed");
  }
  return error;
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

/**
 * Exported for the RDAP provider client (`reputation/rdap-node.ts`), which sits
 * outside L0 but must map the same OpenSSL codes to the same cause. Module-level
 * only — deliberately absent from `transport/index.ts`, like `NodeConnectionPorts`.
 */
export function isCertificateError(code: string | null): boolean {
  return code !== null && (
    code.startsWith("ERR_TLS_CERT") ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID"
  );
}
