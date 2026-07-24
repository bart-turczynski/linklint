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
 * no-op) and recomputed downstream; pure validity errors are treated as still-trusted
 * so trust and validity stay independent axes in the normalized evidence.
 */

import { isIP } from "node:net";
import {
  connect as connectTls,
  type DetailedPeerCertificate,
  type TLSSocket,
} from "node:tls";

import { createSafeTlsInspector, type CreateSafeTlsInspectorOptions } from "./tls-inspect.js";
import { NodeResolver } from "./node-resolver.js";
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
  constructor(readonly code: "connect-refused" | "connect-timeout" | "tls-handshake") {
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

/** Validity errors that do not, on their own, mean the chain is untrusted. */
const VALIDITY_ONLY_ERRORS = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"]);

/** Hard cap on presented certificates walked from the peer chain. */
const MAX_OBSERVED_CHAIN = 16;

class NodeTlsObserver implements TlsObservationPort {
  observe(request: TlsObserveConnectRequest): Promise<TlsHandshakeObservation> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const identity = request.serverName;
      const socket: TLSSocket = connectTls({
        host: request.address,
        port: request.port,
        rejectUnauthorized: false,
        ALPNProtocols: ["http/1.1"],
        // Identity is recomputed downstream from preserved DER, never inferred here.
        checkServerIdentity: () => undefined,
        ...(isIP(identity) === 0 ? { servername: identity } : {}),
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });

      const fail = (error: Error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (request.signal?.aborted) reject(new NodeAbortError());
        else if (isCode(error, "ECONNREFUSED")) reject(new NodeTlsObserveFailure("connect-refused"));
        else if (isCode(error, "ETIMEDOUT")) reject(new NodeTlsObserveFailure("connect-timeout"));
        else reject(new NodeTlsObserveFailure("tls-handshake"));
      };

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
  const authorized = socket.authorized;
  const authorizationErrorCode = errorCodeOf(socket.authorizationError);
  const chainTrusted =
    authorized || (authorizationErrorCode !== null && VALIDITY_ONLY_ERRORS.has(authorizationErrorCode));
  return {
    serverName: request.serverName,
    remoteAddress: socket.remoteAddress ?? request.address,
    remotePort: socket.remotePort ?? request.port,
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

function errorCodeOf(error: Error | undefined): string | null {
  if (!error) return null;
  if ("code" in error && typeof error.code === "string") return error.code;
  return error.message === "" ? null : error.message;
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
