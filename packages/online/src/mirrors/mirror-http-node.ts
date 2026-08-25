/**
 * Bounded Node HTTP engine for the caller-owned feed downloads (LINK-mpkglaqb).
 *
 * `updateUrlhausSnapshot` and `updatePhishTankSnapshot` have always required an
 * injected HTTP client and shipped without one, so no caller could actually
 * refresh either mirror. This is that implementation, and it is deliberately
 * ONE implementation: the two feeds differ in where their credential is
 * revealed and in nothing this file does, so `urlhaus-node.ts` and
 * `phishtank-node.ts` are thin per-feed faces over this engine rather than two
 * copies of the same socket, address, budget and decode wiring drifting apart.
 *
 * WHY IT IS NOT THE SAFE TRANSPORT. Same reason as
 * `reputation/rdap-node.ts`, whose shape this follows: abuse.ch and PhishTank
 * are PROVIDER connections, not inspected destinations. L0
 * (`transport/safe-transport.ts`) authorizes a request only when it carries a
 * `destination-fetch` authorization whose URL equals the request URL, so
 * routing a feed download through it would mean authorizing the *feed host* as
 * a fetched destination. `docs/online-runtime-boundary.md` forbids exactly that
 * conflation: "destination-fetch authorization does not imply
 * provider-disclosure consent, or vice versa".
 *
 * WHAT IT STILL BORROWS. Sitting outside L0 is not licence to connect
 * anywhere. Every address this engine would connect to is classified by the
 * SAME policy L0 uses — {@link classifyTransportAddress}, reached through a
 * custom `dns.lookup` gate so the classified answers are literally the ones
 * Node then connects to. A caller-supplied `dumpUrl` / `baseUrl` is the obvious
 * way to point a credentialed download at loopback or cloud metadata, and this
 * gate is what stops it.
 *
 * WHERE THE BUDGETS DIVERGE, AND WHY. The RDAP client borrows L0's numbers
 * verbatim because an RDAP lookup is one small JSON document. A whole-dataset
 * feed export is not: L0's 1 MiB encoded / 4 MiB decoded / 10 s defaults would
 * refuse every real URLhaus or PhishTank download. So the SHAPE
 * ({@link TransportPolicy}) and the address TABLE stay single-sourced, and only
 * the magnitudes are raised, as the named
 * {@link DEFAULT_MIRROR_DOWNLOAD_POLICY} — still bounded, still one place,
 * still caller-overridable. The header budgets are not raised: a response head
 * is a response head whatever the body weighs.
 *
 * DISCLOSURE. Both feeds declare `credentials: { kind: "required" }` and both
 * updaters reveal that credential at the moment of the request — URLhaus into
 * an `Auth-Key` request header, PhishTank into the download URL's path. Three
 * consequences are enforced here:
 *
 *   1. **Nothing is read from ambient configuration.** No `process.env`, no
 *      home directory, no global agent. Every knob arrives through the factory
 *      options, and the agent is constructed per request so no ambient proxy or
 *      pooled socket applies.
 *   2. **No error ever carries the request URL or a header value.** A typed
 *      failure's `detail` carries only an address, a scheme, or an encoding
 *      name — never a path (which is PhishTank's key) and never a header value
 *      (which is URLhaus's). The mapper below builds every failure from a code
 *      and a bounded detail rather than from `error.message`.
 *   3. **A cleartext URL is refused by default.** Unlike RDAP — which carries
 *      no credential and so accepts `http:` and defers the scheme choice to the
 *      layer above — every request this engine makes carries a caller secret,
 *      and this engine is the only layer that sees the resolved URL. So it owns
 *      the scheme policy: non-HTTPS is refused with `unsupported-scheme` unless
 *      the caller sets `allowInsecureUrl`, the documented hermetic-test seam
 *      that `rdap-bootstrap-updater.ts` spells `allowInsecureBootstrapUrl`.
 *
 * ONE REQUEST, NO REDIRECT FOLLOWING. A 3xx is returned verbatim, `Location`
 * header included, and the updater turns it into a typed `*-http-error`.
 * Following it would mean re-sending a caller credential to a host the caller
 * never named, which is precisely what
 * `docs/online-runtime-boundary.md` forbids when it says provider
 * authorization headers "are always stripped before a destination request or
 * cross-origin redirect". Not following at all is the stronger version of that
 * rule, and neither updater owns a redirect chain that could take it over.
 */

import { lookup as dnsLookup, type LookupAllOptions, type LookupAddress } from "node:dns";
import {
  Agent as HttpAgent,
  request as httpRequest,
  type ClientRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
} from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";

import { classifyTransportAddress } from "../transport/address.js";
import {
  ContentDecompressionError,
  DecompressedLimitError,
  UnsupportedContentEncodingError,
  decodeResponseBody,
} from "../transport/decompression.js";
import { systemErrorCode } from "../transport/node-resolver.js";
import { isCertificateError } from "../transport/node.js";
import { resolveTransportPolicy, type TransportPolicy } from "../transport/policy.js";
import type { TransportAddressDecision, TransportCauseCode } from "../transport/types.js";

/**
 * The request shape both feed clients present. Structurally identical to
 * `UrlhausHttpRequest` and `PhishTankHttpRequest`, which is what lets one
 * engine satisfy both ports without either port learning the other exists.
 */
export interface MirrorHttpRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
}

export interface MirrorHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/**
 * How this engine names its failures. Each feed supplies its own error classes
 * so `instanceof UrlhausHttpFailure` stays meaningful and so the updaters'
 * `describeError` — which reports `error.name` and nothing else — names the
 * feed that failed.
 */
export interface MirrorHttpFailures {
  failure(code: TransportCauseCode, detail?: string | null): Error;
  abort(): Error;
}

/**
 * Bounds for one feed download. The header bounds are L0's; the body and time
 * bounds are raised because a whole-dataset export is not a single document.
 * Merged UNDER any caller `policy`, so a caller who wants L0's numbers back
 * simply passes them.
 */
export const DEFAULT_MIRROR_DOWNLOAD_POLICY: Readonly<Partial<TransportPolicy>> = Object.freeze({
  /** 64 MiB encoded — roughly an order of magnitude over either feed today. */
  maxResponseBytes: 67_108_864,
  /** 256 MiB decoded, the same headroom applied after content decoding. */
  maxDecompressedBytes: 268_435_456,
  /** Two minutes: a multi-megabyte export over a slow link is not a hung socket. */
  maxTotalTimeMs: 120_000,
});

export interface NodeMirrorHttpClientOptions {
  /**
   * Bounds for one download. Only `maxResponseBytes`, `maxDecompressedBytes`,
   * `maxTotalTimeMs`, `maxResponseHeaderBytes` and `maxResponseHeaderFields`
   * are meaningful here — the hop and throughput budgets are properties of an
   * L0 *session* and have no analogue in a single provider request. Anything
   * left unset falls back to {@link DEFAULT_MIRROR_DOWNLOAD_POLICY}, then to
   * the L0 defaults.
   */
  readonly policy?: Partial<TransportPolicy>;
  /**
   * The address policy applied to every resolved answer before a socket is
   * opened. Defaults to {@link classifyTransportAddress}, the same table L0
   * pins destinations with.
   *
   * Injectable for the same reason `createNodeSafeTransport` accepts a partial
   * policy: the default correctly refuses loopback, which is the only address a
   * hermetic live test can serve from. Supplying a permissive decision is a
   * test seam, not a production mode — the default is always the real table.
   */
  readonly classifyAddress?: (address: string) => TransportAddressDecision;
  /**
   * Permit an `http:` download URL. Off by default because every request
   * carries a caller credential; exists so a hermetic loopback test can serve
   * a feed, and is documented as a test seam exactly as
   * `allowInsecureBootstrapUrl` is.
   */
  readonly allowInsecureUrl?: boolean;
}

/** Offered on every request; a caller header of the same name still wins. */
const MIRROR_ACCEPT = "text/csv, text/plain;q=0.9, application/zip;q=0.8, */*;q=0.5";
const MIRROR_ACCEPT_ENCODING = "gzip, deflate, br";

/** RFC 9110 field-name token. Anything else never reaches the wire. */
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** CR, LF and NUL are the request-splitting characters; also refuse bare DEL. */
const FORBIDDEN_HEADER_VALUE = /[\0\r\n\x7f]/;

/**
 * Side-effect-free factory. Network activity begins only with a request.
 *
 * Returns a bare send function rather than an object, so each feed module can
 * hand back a value typed as ITS port (`UrlhausHttpClient`,
 * `PhishTankHttpClient`) and the package's public surface stays the capability
 * contract rather than a shared implementation.
 */
export function createNodeMirrorHttpClient(
  failures: MirrorHttpFailures,
  options: NodeMirrorHttpClientOptions = {},
): (request: MirrorHttpRequest) => Promise<MirrorHttpResponse> {
  const client = new NodeMirrorHttpClient(
    resolveTransportPolicy({ ...DEFAULT_MIRROR_DOWNLOAD_POLICY, ...options.policy }),
    options.classifyAddress ?? classifyTransportAddress,
    options.allowInsecureUrl === true,
    failures,
  );
  return (request) => client.request(request);
}

class NodeMirrorHttpClient {
  constructor(
    private readonly policy: TransportPolicy,
    private readonly classify: (address: string) => TransportAddressDecision,
    private readonly allowInsecureUrl: boolean,
    private readonly failures: MirrorHttpFailures,
  ) {}

  async request(request: MirrorHttpRequest): Promise<MirrorHttpResponse> {
    if (isAborted(request.signal)) throw this.failures.abort();
    const url = this.providerUrl(request.url);
    const headers = this.requestHeaders(request.headers);

    // One controller composes the caller's cancellation with this client's own
    // deadline, so the socket, the header parse and the body read are all
    // bounded by the same signal rather than by three independent timers.
    const controller = new AbortController();
    const onCallerAbort = (): void => controller.abort();
    request.signal?.addEventListener("abort", onCallerAbort, { once: true });
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.policy.maxTotalTimeMs);
    deadline.unref();

    try {
      return await this.send(url, headers, controller.signal);
    } catch (error) {
      // Caller cancellation is reported ahead of the deadline: an abort that
      // races the timer is still the caller's abort.
      if (isAborted(request.signal)) throw this.failures.abort();
      if (timedOut) throw this.failures.failure("http-timeout");
      throw error;
    } finally {
      clearTimeout(deadline);
      request.signal?.removeEventListener("abort", onCallerAbort);
    }
  }

  private send(
    url: URL,
    headers: Readonly<Record<string, string>>,
    signal: AbortSignal,
  ): Promise<MirrorHttpResponse> {
    // An IP-LITERAL host never reaches the lookup gate: `net.connect` skips
    // resolution entirely when `host` is already an address, so a configured
    // `dumpUrl` of `http://169.254.169.254/` would otherwise walk straight past
    // the policy. Classified here for the same reason `transport/pin.ts` treats
    // a literal as its own single "resolved" answer.
    const host = unbracket(url.hostname);
    if (isIP(host) !== 0) {
      const decision = this.classify(host);
      if (!decision.allowed) {
        throw this.failures.failure(
          "prohibited-address",
          `${host} (${decision.category ?? "invalid"})`,
        );
      }
    }

    const secure = url.protocol === "https:";
    const dispatch = secure ? httpsRequest : httpRequest;
    // Constructed per request and never kept alive: no pooled socket outlives
    // the lookup that classified its address, and no ambient/global agent
    // configuration (proxy included) applies.
    const agent = secure
      ? new HttpsAgent({ keepAlive: false })
      : new HttpAgent({ keepAlive: false });

    return new Promise<MirrorHttpResponse>((resolve, reject) => {
      let settled = false;
      let clientRequest: ClientRequest | undefined;
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        clientRequest?.destroy();
        reject(error);
      };

      try {
        clientRequest = dispatch(
          {
            protocol: url.protocol,
            hostname: host,
            port: url.port === "" ? (secure ? 443 : 80) : Number(url.port),
            path: `${url.pathname}${url.search}`,
            method: "GET",
            headers,
            agent,
            // The address gate. Node connects to exactly the answers this
            // returns, and it returns none that the policy refused.
            lookup: this.policedLookup(),
            // The tight seam for the header-byte budget: llhttp stops parsing
            // at this bound, so an oversized head never finishes being
            // buffered, and the limit belongs to this boundary rather than to
            // whatever `--max-http-header-size` the host process was launched
            // with.
            maxHeaderSize: this.policy.maxResponseHeaderBytes,
            signal,
          },
          (response: IncomingMessage) => {
            void this.readResponse(response).then(
              (value) => {
                if (settled) return;
                settled = true;
                resolve(value);
              },
              (error: unknown) => fail(error),
            );
          },
        );
      } catch (error) {
        // `http.request` validates the port, the option shape and the whole
        // header block SYNCHRONOUSLY, so these throws never reach the `error`
        // event and would otherwise escape this boundary as raw Node errors —
        // untyped, and carrying a message this client never inspected. Routed
        // through the same mapper as every asynchronous failure instead.
        fail(this.requestFailure(error));
        return;
      }

      clientRequest.once("error", (error: unknown) => fail(this.requestFailure(error)));
      clientRequest.end();
    });
  }

  /**
   * Reads and decodes one response under the byte budgets.
   *
   * No re-check of `socket.remoteAddress` happens here, deliberately. L0 needs
   * one because its connector is an injected port that could report a peer it
   * did not connect to; here the classified lookup answer and the connect are
   * the same `net.Socket` call, so a re-check could only disagree with itself —
   * and would misfire on an IPv4-mapped peer form.
   */
  private async readResponse(response: IncomingMessage): Promise<MirrorHttpResponse> {
    // `rawHeaders` is the field OCCURRENCE count, which is the axis the
    // parser's byte limit does not cover: thousands of tiny fields fit inside a
    // byte cap.
    if (response.rawHeaders.length / 2 > this.policy.maxResponseHeaderFields) {
      response.destroy();
      throw this.failures.failure("response-headers-too-large");
    }

    const encoded = await this.readEncodedBody(response);
    return {
      status: response.statusCode ?? 0,
      headers: flattenHeaders(response.headers),
      body: this.decode(encoded, response.headers),
    };
  }

  private async readEncodedBody(response: IncomingMessage): Promise<Uint8Array> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of response) {
      const buffer = chunk as Buffer;
      total += buffer.byteLength;
      if (total > this.policy.maxResponseBytes) {
        response.destroy();
        throw this.failures.failure("response-too-large", String(this.policy.maxResponseBytes));
      }
      chunks.push(buffer);
    }
    return new Uint8Array(Buffer.concat(chunks, total));
  }

  private decode(encoded: Uint8Array, headers: IncomingHttpHeaders): string {
    try {
      const decoded = decodeResponseBody(
        encoded,
        headerLists(headers),
        this.policy.maxDecompressedBytes,
      );
      return Buffer.from(decoded).toString("utf8");
    } catch (error) {
      if (error instanceof DecompressedLimitError) {
        throw this.failures.failure(
          "decompressed-response-too-large",
          String(this.policy.maxDecompressedBytes),
        );
      }
      if (error instanceof UnsupportedContentEncodingError) {
        throw this.failures.failure("unsupported-content-encoding", error.encoding);
      }
      if (error instanceof ContentDecompressionError) {
        throw this.failures.failure("decompression-error");
      }
      throw error;
    }
  }

  /**
   * Merge the caller's headers over this client's defaults, lower-casing every
   * name so a caller cannot set the same field twice in two spellings.
   *
   * The caller's map is where the credential lives, so it wins — but it is
   * VALIDATED first. A name that is not an RFC 9110 token, or a value carrying
   * CR/LF/NUL, is a request-splitting attempt and is refused before a socket
   * opens. The refusal names the header but never its value.
   */
  private requestHeaders(
    caller: Readonly<Record<string, string>>,
  ): Readonly<Record<string, string>> {
    const headers: Record<string, string> = {
      accept: MIRROR_ACCEPT,
      "accept-encoding": MIRROR_ACCEPT_ENCODING,
    };
    for (const [name, value] of Object.entries(caller)) {
      if (!HEADER_NAME.test(name)) {
        throw this.failures.failure("http-malformed", "invalid request header name");
      }
      if (FORBIDDEN_HEADER_VALUE.test(value)) {
        throw this.failures.failure("http-malformed", `invalid value for ${name.toLowerCase()}`);
      }
      headers[name.toLowerCase()] = value;
    }
    return headers;
  }

  /**
   * Parse the download URL and refuse the shapes that must never reach a
   * socket.
   *
   * Userinfo is refused rather than dropped, and the refusal carries no detail
   * at all: the whole point is that a credential-shaped URL must not be echoed
   * anywhere. `unsupported-scheme` carries the protocol, which is a fixed
   * token, never the path — PhishTank's app key lives in the path.
   */
  private providerUrl(raw: string): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw this.failures.failure("invalid-url");
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && this.allowInsecureUrl)) {
      throw this.failures.failure("unsupported-scheme", url.protocol);
    }
    if (url.username !== "" || url.password !== "") {
      throw this.failures.failure("url-credentials");
    }
    url.hash = "";
    return url;
  }

  /**
   * A `dns.lookup` replacement that classifies every answer before handing any
   * of them back. Node calls it in one of two shapes depending on whether
   * happy-eyeballs family selection is active, so both are answered; either way
   * the set Node may connect to is the set that passed the policy.
   */
  private policedLookup(): LookupFunction {
    const classify = this.classify;
    const failures = this.failures;
    return (hostname, options, callback): void => {
      const lookupOptions: LookupAllOptions = {
        all: true,
        verbatim: true,
        ...(options.family === undefined || options.family === 0
          ? {}
          : { family: options.family }),
        ...(options.hints === undefined ? {} : { hints: options.hints }),
      };
      dnsLookup(hostname, lookupOptions, (error, answers: LookupAddress[]) => {
        if (error) {
          callback(error, "");
          return;
        }
        if (answers.length === 0) {
          callback(failures.failure("dns-not-found", hostname), "");
          return;
        }
        for (const answer of answers) {
          const decision = classify(answer.address);
          if (!decision.allowed) {
            callback(
              failures.failure(
                "prohibited-address",
                `${answer.address} (${decision.category ?? "invalid"})`,
              ),
              "",
            );
            return;
          }
        }
        if (options.all === true) {
          callback(null, answers);
          return;
        }
        const first = answers[0]!;
        callback(null, first.address, first.family);
      });
    };
  }

  /**
   * Map a `node:http` client error onto the typed cause it represents.
   *
   * Nothing from `error.message` survives: a Node error raised while sending a
   * credentialed request can quote the request URL or a header name, and this
   * boundary answers with a code and a fixed detail instead.
   */
  private requestFailure(error: unknown): unknown {
    // The lookup gate's refusal travels out through the socket's error channel;
    // it is already one of ours, and re-wrapping would lose its detail.
    if (isOwnFailure(error)) return error;
    const code = systemErrorCode(error);
    switch (code) {
      case "ABORT_ERR":
        return this.failures.abort();
      case "ECONNREFUSED":
        return this.failures.failure("connect-refused");
      case "ETIMEDOUT":
        return this.failures.failure("connect-timeout");
      case "ENOTFOUND":
      case "ENODATA":
        return this.failures.failure("dns-not-found");
      case "EAI_AGAIN":
      case "ETIMEOUT":
        return this.failures.failure("dns-timeout");
      case "ECONNRESET":
      case "EPIPE":
        return this.failures.failure("http-reset");
      case "HPE_HEADER_OVERFLOW":
        return this.failures.failure("response-headers-too-large");
      case "ERR_INVALID_CHAR":
      case "ERR_INVALID_HTTP_TOKEN":
        return this.failures.failure("http-malformed", "invalid request header");
      default:
        if (isCertificateError(code)) return this.failures.failure("tls-certificate");
        if (code !== null && code.startsWith("ERR_TLS")) {
          return this.failures.failure("tls-handshake");
        }
        return this.failures.failure("http-error");
    }
  }
}

/**
 * Whether an error already came out of this engine. Recognized structurally —
 * a `code` drawn from the transport vocabulary plus a `detail` slot — because
 * the concrete classes belong to the per-feed modules, and importing them here
 * would make the engine depend on its own callers.
 */
function isOwnFailure(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    typeof (error as { code?: unknown }).code === "string" &&
    "detail" in error
  );
}

function headerLists(headers: IncomingHttpHeaders): Readonly<Record<string, readonly string[]>> {
  const normalized: Record<string, readonly string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    normalized[name.toLowerCase()] = Array.isArray(value) ? [...value] : [String(value)];
  }
  return normalized;
}

/** The contract's header shape: one string per field name. */
function flattenHeaders(headers: IncomingHttpHeaders): Readonly<Record<string, string>> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    normalized[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return normalized;
}

/**
 * Read through a function so the check is a live read of the signal rather than
 * a value the compiler narrowed at the top of `request()` — the whole point is
 * that it can flip while the request is in flight.
 */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function unbracket(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}
