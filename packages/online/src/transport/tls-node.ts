/**
 * Built-in Node TLS observation port and inspector factory (LINK-fgdawgnj, M7a).
 *
 * The observer connects to a pre-pinned address with the original-host SNI and
 * certificate validation DISABLED (`rejectUnauthorized: false`) so a certificate can
 * be OBSERVED even when it would be rejected. The socket is read once and destroyed
 * immediately — it is never reused, never handed to an HTTP layer, and never treated
 * as a trusted connection. This port is deliberately separate from the fetch
 * connector so observe mode cannot leak into the fail-closed fetch path.
 *
 * Hostname identity is excluded from the socket verdict (checkServerIdentity is a
 * no-op) and recomputed downstream, so identity stays an independent axis.
 *
 * Chain trust is reported exactly as the verifier decided it, with no reinterpretation
 * (LINK-zgmixagu). OpenSSL exposes only ONE verification error even when several
 * faults coexist, so the codes are provably ambiguous: the committed `expired` leaf
 * signed by the private test CA reports `CERT_HAS_EXPIRED` whether or not that CA is
 * trusted. A rule that discounted "validity-only" codes therefore reported an
 * expired-AND-untrusted chain as trusted. Validity remains an independent axis anyway
 * — it is recomputed downstream from the leaf's own notBefore/notAfter against the
 * observation instant — and `trustErrorCode` carries the verifier's reason verbatim so
 * a consumer can tell "trust was not established, and expiry is what it stopped at"
 * from a forged-signature verdict.
 */

import { isIP } from "node:net";
import {
  connect as connectTls,
  type DetailedPeerCertificate,
  type TLSSocket,
} from "node:tls";

import { createSafeTlsInspector, type CreateSafeTlsInspectorOptions } from "./tls-inspect.js";
import { NodeResolver } from "./node-resolver.js";
import { observedPeer } from "./peer.js";
import { SystemClock } from "./system-clock.js";
import type { TlsInspectionPolicy } from "./tls-types.js";
import type {
  SafeTlsInspector,
  TlsHandshakeObservation,
  TlsObservationPort,
  TlsObserveConnectRequest,
} from "./tls-types.js";
import type { ResolverPort } from "./types.js";

class NodeTlsObserveFailure extends Error {
  constructor(
    readonly code: "connect-refused" | "connect-timeout" | "connect-error" | "tls-handshake",
  ) {
    super("node tls observation failed");
    this.name = "NodeTlsObserveFailure";
  }
}

class NodeAbortError extends Error {
  constructor() {
    super("node tls observation aborted");
    this.name = "AbortError";
  }
}

/** Hard cap on presented certificates walked from the peer chain. */
const MAX_OBSERVED_CHAIN = 16;

/**
 * Internal to the package — deliberately absent from `transport/index.ts`. It is
 * exported from this module so the live loopback regression can drive the real
 * socket and read the raw handshake verdict, which no fixture can prove
 * (LINK-zgmixagu).
 */
export class NodeTlsObserver implements TlsObservationPort {
  observe(request: TlsObserveConnectRequest): Promise<TlsHandshakeObservation> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const identity = request.serverName;
      // Declared before the dispatch so the synchronous catch below can settle
      // without one. Nothing is destroyed on that path: no socket was ever
      // constructed.
      let socket: TLSSocket;

      const fail = (error: Error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (request.signal?.aborted) reject(new NodeAbortError());
        else if (isCode(error, "ECONNREFUSED")) reject(new NodeTlsObserveFailure("connect-refused"));
        else if (isCode(error, "ETIMEDOUT")) reject(new NodeTlsObserveFailure("connect-timeout"));
        else reject(new NodeTlsObserveFailure("tls-handshake"));
      };

      // `tls.connect` validates its options inside the socket constructor and
      // THROWS rather than emitting `error`, so a refused option escapes before
      // `fail` is attached — the same bare-call-in-executor shape
      // `transport/node.ts` fixed in `NodeConnectionPorts.request` and
      // `openSocket`. Left bare, the executor turned such a throw into a
      // rejection carrying a raw Node error: untyped at this port, and reported
      // one layer up only because `tls-inspect.ts` happens to floor an
      // unrecognized connect-phase rejection at `connect-error`.
      //
      // The guard below already covers the one synchronous throw known to be
      // reachable here — Node 26 raises `ERR_INVALID_ARG_VALUE` from
      // `tls.connect` for an IP `servername`, where Node 24 only warns
      // (DEP0123), and both majors are gated (LINK-bgcfgujq). That is precisely
      // why this catch is not speculative: the failure class has materialized in
      // this exact call once already, and was survived only because someone
      // anticipated it. A boundary typed only for the throws its authors
      // enumerated is not typed. `test/tls-observe-live.test.ts` drives it
      // through the port surface, where an out-of-range port IS reachable, so it
      // is not dead code.
      try {
        socket = connectTls({
          host: request.address,
          port: request.port,
          rejectUnauthorized: false,
          ALPNProtocols: ["http/1.1"],
          // Identity is recomputed downstream from preserved DER, never inferred here.
          checkServerIdentity: () => undefined,
          ...(isIP(identity) === 0 ? { servername: identity } : {}),
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        });
      } catch {
        // A local option Node refused: no socket exists to destroy, no peer was
        // contacted, and nothing was sent. `connect-error` is what the connect
        // phase reports for this anyway, stated here rather than inferred from
        // an escaped `RangeError`.
        settled = true;
        reject(new NodeTlsObserveFailure("connect-error"));
        return;
      }

      socket.once("error", fail);
      socket.once("secureConnect", () => {
        if (settled) return;
        settled = true;
        socket.removeListener("error", fail);
        try {
          const observation = captureObservation(socket, request);
          socket.destroy();
          resolve(observation);
        } catch (error) {
          socket.destroy();
          reject(error instanceof Error ? error : new NodeTlsObserveFailure("tls-handshake"));
        }
      });
    });
  }
}

function captureObservation(
  socket: TLSSocket,
  request: TlsObserveConnectRequest,
): TlsHandshakeObservation {
  // Report the OBSERVED peer or nothing. Falling back to `request.address` /
  // `request.port` here would hand the inspector its own pin back and let the
  // address check confirm itself (LINK-abozdqtp).
  const peer = observedPeer(socket);
  if (peer === null) throw new NodeTlsObserveFailure("connect-error");
  const authorized = socket.authorized;
  const authorizationErrorCode = errorCodeOf(socket.authorizationError);
  // Trust is the verifier's verdict, unmodified. Nothing here can subtract a fault
  // from a result that reports at most one of them (LINK-zgmixagu).
  const chainTrusted = authorized;
  return {
    serverName: request.serverName,
    remoteAddress: peer.address,
    remotePort: peer.port,
    certificateChain: collectChain(socket.getPeerCertificate(true)),
    chainTrusted,
    trustErrorCode: authorized ? null : authorizationErrorCode,
    protocolVersion: socket.getProtocol(),
  };
}

/** Walk the peer chain leaf-first into DER byte arrays, stopping at the root/self. */
function collectChain(
  leaf: DetailedPeerCertificate | Record<string, never>,
): readonly Uint8Array[] {
  const chain: Uint8Array[] = [];
  let current = leaf as DetailedPeerCertificate | undefined;
  const seen = new Set<string>();
  while (current && current.raw && chain.length < MAX_OBSERVED_CHAIN) {
    const fingerprint = current.fingerprint256 ?? String(chain.length);
    if (seen.has(fingerprint)) break;
    seen.add(fingerprint);
    chain.push(new Uint8Array(current.raw));
    const next = current.issuerCertificate;
    if (!next || next === current) break;
    current = next;
  }
  return chain;
}

/**
 * The verifier's reason code, from whatever shape Node hands over.
 *
 * `@types/node` declares `TLSSocket.authorizationError` as `Error`, but Node 26
 * populates it with the bare OpenSSL code STRING (`"CERT_HAS_EXPIRED"`). Reading it as
 * an object made this throw a `TypeError` for every unauthorized peer, which the
 * observe loop turned into a `tls-handshake` rejection — so no untrusted chain ever
 * reached the normalizer, and the trust rule this function feeds had no live coverage
 * to contradict it (found while pinning LINK-zgmixagu). Accept both shapes.
 */
function errorCodeOf(error: unknown): string | null {
  if (error === null || error === undefined) return null;
  if (typeof error === "string") return error === "" ? null : error;
  if (typeof error !== "object") return null;
  if ("code" in error && typeof error.code === "string") return error.code;
  const message = "message" in error ? error.message : undefined;
  return typeof message === "string" && message !== "" ? message : null;
}

function isCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

export interface CreateNodeSafeTlsInspectorOptions {
  readonly policy?: Partial<TlsInspectionPolicy>;
  readonly resolver?: ResolverPort;
}

/** Side-effect-free factory. Network activity begins only with an `inspect()` call. */
export function createNodeSafeTlsInspector(
  options: CreateNodeSafeTlsInspectorOptions = {},
): SafeTlsInspector {
  const inspectorOptions: CreateSafeTlsInspectorOptions = {
    resolver: options.resolver ?? new NodeResolver(),
    observer: new NodeTlsObserver(),
    clock: new SystemClock(),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
  };
  return createSafeTlsInspector(inspectorOptions);
}
