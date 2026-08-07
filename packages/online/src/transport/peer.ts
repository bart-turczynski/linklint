/**
 * Observed peer endpoint of a connected socket (LINK-abozdqtp).
 *
 * The built-in HTTP and TLS adapters used to report
 * `socket.remoteAddress ?? request.address` and `socket.remotePort ?? request.port`.
 * Ordinary successful Node sockets populate both fields, so no bypass was
 * reproduced — but the fallback substituted the REQUESTED pin for a MISSING
 * observation, and the caller then compares that value against the same pin. A
 * socket that reported nothing would have verified itself.
 *
 * So the adapters read only what the socket observed: a peer whose address is not
 * a syntactically valid IP literal, or whose port is not a usable port number, is
 * an operational failure of the connect phase, not a confirmation.
 */

import { isIP } from "node:net";

/**
 * The peer fields of a socket. Both are declared optional because Node leaves
 * them `undefined` on a socket that is not (or is no longer) connected.
 */
export interface SocketPeerFields {
  readonly remoteAddress?: string | undefined;
  readonly remotePort?: number | undefined;
}

/** A peer endpoint the socket actually reported. Never derived from a request. */
export interface ObservedPeer {
  readonly address: string;
  readonly port: number;
}

/**
 * The socket's observed peer endpoint, or `null` when it is absent or malformed.
 * A `null` result means the connection cannot be checked against the pinned
 * destination, which the adapters treat as a failed connect.
 */
export function observedPeer(socket: SocketPeerFields): ObservedPeer | null {
  const address = socket.remoteAddress;
  const port = socket.remotePort;
  if (typeof address !== "string" || isIP(address) === 0) return null;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65_535) return null;
  return { address, port };
}
