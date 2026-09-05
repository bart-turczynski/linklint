/**
 * Bounded Node PhishTank HTTP client (LINK-mpkglaqb).
 *
 * `updatePhishTankSnapshot` has always required an injected
 * {@link PhishTankHttpClient} and shipped without one, so no caller could
 * actually refresh a PhishTank mirror. This is that implementation.
 *
 * The socket, address-policy, budget and decode wiring lives in
 * `mirror-http-node.ts`, shared with the URLhaus client — read that file for
 * why a feed download sits outside the L0 destination boundary, which parts of
 * L0's policy it still borrows, and how far it follows a redirect. This module
 * owns only what is PhishTank-specific: the error identity the updater reports,
 * and the note below about where the credential goes.
 *
 * CREDENTIAL SHAPE, AND WHY IT MAKES THE ERROR CHANNEL LOAD-BEARING.
 * `PHISHTANK_SOURCE_DESCRIPTOR` declares
 * `credentials: { kind: "optional", scheme: "app-key" }` — optional because
 * PhishTank serves this feed unkeyed (LINK-plfzjlxg) — and when a caller does
 * have a key, PhishTank puts it in the download URL's PATH rather than in a
 * header: `${baseUrl}/${appKey}/online-valid.csv`. So for this feed the request
 * URL may itself be a secret, which is enough: this client cannot know whether
 * the URL it was handed carries one, so it treats every one of them as though it
 * does. The rule that no failure may carry a path — enforced in
 * `mirror-http-node.ts`, where every typed failure is built from a code plus a
 * bounded detail rather than from `error.message` — is the thing standing
 * between an app key and a log line. `unsupported-scheme` reports the protocol,
 * `prohibited-address` reports an address, `url-credentials` reports nothing at
 * all. None of them can quote the path.
 *
 * The descriptive `User-Agent` PhishTank requires arrives through the updater's
 * header map like any other header; this client adds nothing of its own beyond
 * `Accept` and `Accept-Encoding`, and reads no `process.env`, home directory or
 * ambient configuration.
 */

import {
  createNodeMirrorHttpClient,
  type NodeMirrorHttpClientOptions,
} from "./mirror-http-node.js";
import type {
  PhishTankHttpClient,
  PhishTankHttpRequest,
  PhishTankHttpResponse,
} from "./phishtank-types.js";
import type { TransportCauseCode } from "../transport/types.js";

/**
 * A typed provider-transport failure. Reuses L0's {@link TransportCauseCode}
 * vocabulary rather than inventing a third one; `detail` carries the one piece
 * of context the code alone cannot (the refused address, the scheme, the
 * unsupported encoding) and never carries response content, a request path, or
 * a header value.
 *
 * `updatePhishTankSnapshot` reports `error.name` and nothing else, so this
 * class is what turns a transport failure into a legible
 * `phishtank-network-error`.
 */
export class PhishTankHttpFailure extends Error {
  constructor(
    readonly code: TransportCauseCode,
    readonly detail: string | null = null,
  ) {
    super("PhishTank provider request failed");
    this.name = "PhishTankHttpFailure";
  }
}

/** Cancellation, named so the updater reports `phishtank-caller-aborted`. */
export class PhishTankHttpAbortError extends Error {
  constructor() {
    super("PhishTank provider request aborted");
    this.name = "AbortError";
  }
}

/**
 * Options for {@link createNodePhishTankHttpClient}.
 *
 * There is deliberately no `userAgent` knob, unlike the RDAP client:
 * `UpdatePhishTankSnapshotOptions` already owns that field and puts it in the
 * request header map, so a second way to set it would be two sources of truth
 * for one header.
 */
export type NodePhishTankHttpClientOptions = NodeMirrorHttpClientOptions;

/**
 * Side-effect-free factory. Network activity begins only with a request.
 *
 * Internal class, public interface — the concrete client is reached only
 * through {@link PhishTankHttpClient}, so the package's public surface stays
 * the capability contract rather than an implementation.
 */
export function createNodePhishTankHttpClient(
  options: NodePhishTankHttpClientOptions = {},
): PhishTankHttpClient {
  const send = createNodeMirrorHttpClient(
    {
      failure: (code, detail = null) => new PhishTankHttpFailure(code, detail),
      abort: () => new PhishTankHttpAbortError(),
    },
    options,
  );
  return {
    request: (request: PhishTankHttpRequest): Promise<PhishTankHttpResponse> => send(request),
  };
}
