/**
 * Bounded Node URLhaus HTTP client (LINK-mpkglaqb).
 *
 * `updateUrlhausSnapshot` has always required an injected
 * {@link UrlhausHttpClient} and shipped without one, so no caller could
 * actually refresh a URLhaus mirror. This is that implementation.
 *
 * The socket, address-policy, budget and decode wiring lives in
 * `mirror-http-node.ts`, shared with the PhishTank client — read that file for
 * why a feed download sits outside the L0 destination boundary, which parts of
 * L0's policy it still borrows, and why a 3xx is never followed. This module
 * owns only what is URLhaus-specific: the error identity the updater reports,
 * and the note below about where the credential goes.
 *
 * CREDENTIAL SHAPE. `URLHAUS_SOURCE_DESCRIPTOR` declares
 * `credentials: { kind: "required", scheme: "auth-key" }`. The updater reveals
 * that key into an `Auth-Key` request header at the moment of the request; this
 * client forwards the header map it is given and adds nothing of its own beyond
 * `Accept` and `Accept-Encoding`. It reads no `process.env`, no home directory
 * and no ambient configuration, so there is no second place a credential could
 * come from — and no failure it raises carries a header value, so there is no
 * place one could leak to.
 */

import {
  createNodeMirrorHttpClient,
  type NodeMirrorHttpClientOptions,
} from "./mirror-http-node.js";
import type { UrlhausHttpClient, UrlhausHttpRequest, UrlhausHttpResponse } from "./types.js";
import type { TransportCauseCode } from "../transport/types.js";

/**
 * A typed provider-transport failure. Reuses L0's {@link TransportCauseCode}
 * vocabulary rather than inventing a third one; `detail` carries the one piece
 * of context the code alone cannot (the refused address, the scheme, the
 * unsupported encoding) and never carries response content, a request path, or
 * a header value.
 *
 * `updateUrlhausSnapshot` reports `error.name` and nothing else, so this class
 * is what turns a transport failure into a legible `urlhaus-network-error`.
 */
export class UrlhausHttpFailure extends Error {
  constructor(
    readonly code: TransportCauseCode,
    readonly detail: string | null = null,
  ) {
    super("URLhaus provider request failed");
    this.name = "UrlhausHttpFailure";
  }
}

/** Cancellation, named so the updater reports `urlhaus-caller-aborted`. */
export class UrlhausHttpAbortError extends Error {
  constructor() {
    super("URLhaus provider request aborted");
    this.name = "AbortError";
  }
}

/**
 * Options for {@link createNodeUrlhausHttpClient}.
 *
 * There is deliberately no `userAgent` knob, unlike the RDAP client: URLhaus
 * requests carry a caller-built header map already, so a second way to set the
 * same field would be two sources of truth for one header.
 */
export type NodeUrlhausHttpClientOptions = NodeMirrorHttpClientOptions;

/**
 * Side-effect-free factory. Network activity begins only with a request.
 *
 * Internal class, public interface — the concrete client is reached only
 * through {@link UrlhausHttpClient}, so the package's public surface stays the
 * capability contract rather than an implementation.
 */
export function createNodeUrlhausHttpClient(
  options: NodeUrlhausHttpClientOptions = {},
): UrlhausHttpClient {
  const send = createNodeMirrorHttpClient(
    {
      failure: (code, detail = null) => new UrlhausHttpFailure(code, detail),
      abort: () => new UrlhausHttpAbortError(),
    },
    options,
  );
  return {
    request: (request: UrlhausHttpRequest): Promise<UrlhausHttpResponse> => send(request),
  };
}
