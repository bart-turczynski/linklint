/**
 * Bounded Node RDAP HTTP client (LINK-mkddydzr).
 *
 * `fetchRdapDomain` has always required an injected {@link RdapHttpClient} and
 * shipped without one, so no caller could actually run the RDAP source. This is
 * that implementation.
 *
 * WHY IT IS NOT THE SAFE TRANSPORT. An RDAP endpoint is a PROVIDER connection,
 * not an inspected destination. L0 (`transport/safe-transport.ts`) authorizes a
 * request only when it carries a `destination-fetch` authorization whose URL
 * equals the request URL, so routing RDAP through it would mean authorizing the
 * *registry* as a fetched destination. `docs/online-runtime-boundary.md` forbids
 * exactly that conflation: "destination-fetch authorization does not imply
 * provider-disclosure consent, or vice versa". This client therefore sits
 * outside the L0 boundary, as `reputation/types.ts` and `rdap-client.ts` already
 * state it must.
 *
 * WHAT IT STILL BORROWS. Sitting outside L0 is not licence to connect anywhere.
 * A poisoned or hostile bootstrap entry could name a link-local, loopback,
 * cloud-metadata or otherwise prohibited address, so every address this client
 * would connect to is classified by the SAME policy L0 uses —
 * {@link classifyTransportAddress}, reached through a custom `dns.lookup` gate
 * so the classified answers are literally the ones Node then connects to. The
 * byte, header and time bounds come from {@link TransportPolicy} rather than
 * from a second set of numbers invented here.
 *
 * The classification loop is written here rather than reusing
 * `transport/pin.ts`, deliberately: `pinDestination` documents that keeping the
 * decision in one place stops the fetch and observe paths drifting apart, and
 * adding an injectable classifier to it would put a widening seam inside L0.
 * The seam belongs on this side of the boundary, where it is a provider-client
 * option, and the *policy* — the address table — stays single-sourced.
 *
 * DISCLOSURE. `RDAP_SOURCE_DESCRIPTOR` declares `credentials: { kind: "none" }`.
 * This client sends no `Authorization` header, no cookie, and no credential of
 * any kind; a URL carrying userinfo is refused rather than transmitted. Nothing
 * is read from `process.env`, from a home directory, or from any ambient
 * configuration — every knob arrives through the factory options, and the agent
 * is constructed per request so no ambient proxy or pooled socket applies.
 *
 * ONE REQUEST, NO REDIRECT FOLLOWING. `fetchRdapDomain` owns the bounded
 * redirect chain. A 3xx is returned to it verbatim, `Location` header included.
 */

import { lookup as dnsLookup, type LookupAllOptions, type LookupAddress } from "node:dns";
import {
  Agent as HttpAgent,
  request as httpRequest,
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

import type { RdapHttpClient, RdapHttpRequest, RdapHttpResponse } from "./types.js";

/**
 * A typed provider-transport failure. Reuses L0's {@link TransportCauseCode}
 * vocabulary rather than inventing a third one; `detail` carries the one piece
 * of context the code alone cannot (the refused address, the scheme, the
 * unsupported encoding) and never carries response content.
 */
export class RdapHttpFailure extends Error {
  constructor(
    readonly code: TransportCauseCode,
    readonly detail: string | null = null,
  ) {
    super("RDAP provider request failed");
    this.name = "RdapHttpFailure";
  }
}

/** Cancellation, named so `fetchRdapDomain` reports `rdap-caller-aborted`. */
export class RdapHttpAbortError extends Error {
  constructor() {
    super("RDAP provider request aborted");
    this.name = "AbortError";
  }
}

/** RDAP is JSON over HTTP; `q=0.9` keeps a plain-JSON registrar acceptable. */
const RDAP_ACCEPT = "application/rdap+json, application/json;q=0.9";
const RDAP_ACCEPT_ENCODING = "gzip, deflate, br";

export interface NodeRdapHttpClientOptions {
  /**
   * Bounds for one provider request, drawn from the L0 policy so both
   * boundaries state the same numbers. Only `maxResponseBytes`,
   * `maxDecompressedBytes`, `maxTotalTimeMs`, `maxResponseHeaderBytes` and
   * `maxResponseHeaderFields` are meaningful here — the hop and throughput
   * budgets are properties of an L0 *session* and have no analogue in a single
   * provider request.
   */
  readonly policy?: Partial<TransportPolicy>;
  /**
   * The address policy applied to every resolved answer before a socket is
   * opened. Defaults to {@link classifyTransportAddress}, the same table L0
   * pins destinations with.
   *
   * Injectable for the same reason `createNodeSafeTransport` accepts a partial
   * policy: the default correctly refuses loopback, which is the only address a
   * hermetic live test can serve from. Supplying a permissive decision is a test
   * seam, not a production mode — the default is always the real table.
   */
  readonly classifyAddress?: (address: string) => TransportAddressDecision;
  /**
   * Optional `User-Agent`. Omitted entirely by default: the descriptor declares
   * the disclosure as the registrable domain, and an unrequested client
   * identity would widen that without the caller saying so.
   */
  readonly userAgent?: string;
}

/**
 * Side-effect-free factory. Network activity begins only with a request.
 *
 * Internal class, public interface — the concrete client is not exported from
 * `reputation/index.ts`, so the package's public surface stays the capability
 * contract rather than an implementation.
 */
export function createNodeRdapHttpClient(
  options: NodeRdapHttpClientOptions = {},
): RdapHttpClient {
  return new NodeRdapHttpClient(
    resolveTransportPolicy(options.policy),
    options.classifyAddress ?? classifyTransportAddress,
    options.userAgent ?? null,
  );
}

class NodeRdapHttpClient implements RdapHttpClient {
  constructor(
    private readonly policy: TransportPolicy,
    private readonly classify: (address: string) => TransportAddressDecision,
    private readonly userAgent: string | null,
  ) {}

  async request(request: RdapHttpRequest): Promise<RdapHttpResponse> {
    if (isAborted(request.signal)) throw new RdapHttpAbortError();
    const url = providerUrl(request.url);

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
      return await this.send(url, controller.signal);
    } catch (error) {
      // Caller cancellation is reported ahead of the deadline: an abort that
      // races the timer is still the caller's abort.
      if (isAborted(request.signal)) throw new RdapHttpAbortError();
      if (timedOut) throw new RdapHttpFailure("http-timeout");
      throw error;
    } finally {
      clearTimeout(deadline);
      request.signal?.removeEventListener("abort", onCallerAbort);
    }
  }

  private send(url: URL, signal: AbortSignal): Promise<RdapHttpResponse> {
    // An IP-LITERAL host never reaches the lookup gate: `net.connect` skips
    // resolution entirely when `host` is already an address, so a bootstrap
    // entry written as `http://169.254.169.254/` would otherwise walk straight
    // past the policy. Classified here for the same reason `transport/pin.ts`
    // treats a literal as its own single "resolved" answer.
    const host = unbracket(url.hostname);
    if (isIP(host) !== 0) {
      const decision = this.classify(host);
      if (!decision.allowed) {
        throw new RdapHttpFailure(
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
    const agent = secure ? new HttpsAgent({ keepAlive: false }) : new HttpAgent({ keepAlive: false });

    return new Promise<RdapHttpResponse>((resolve, reject) => {
      let settled = false;
      const clientRequest = dispatch(
        {
          protocol: url.protocol,
          hostname: unbracket(url.hostname),
          port: url.port === "" ? (secure ? 443 : 80) : Number(url.port),
          path: `${url.pathname}${url.search}`,
          method: "GET",
          headers: this.requestHeaders(),
          agent,
          // The address gate. Node connects to exactly the answers this returns,
          // and it returns none that the policy refused.
          lookup: this.policedLookup(),
          // The tight seam for the header-byte budget: llhttp stops parsing at
          // this bound, so an oversized head never finishes being buffered, and
          // the limit belongs to this boundary rather than to whatever
          // `--max-http-header-size` the host process was launched with.
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

      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        clientRequest.destroy();
        reject(error);
      };

      clientRequest.once("error", (error: unknown) => fail(requestFailure(error)));
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
  private async readResponse(response: IncomingMessage): Promise<RdapHttpResponse> {
    // `rawHeaders` is the field OCCURRENCE count, which is the axis the parser's
    // byte limit does not cover: thousands of tiny fields fit inside a byte cap.
    if (response.rawHeaders.length / 2 > this.policy.maxResponseHeaderFields) {
      response.destroy();
      throw new RdapHttpFailure("response-headers-too-large");
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
        throw new RdapHttpFailure("response-too-large", String(this.policy.maxResponseBytes));
      }
      chunks.push(buffer);
    }
    return new Uint8Array(Buffer.concat(chunks, total));
  }

  private decode(encoded: Uint8Array, headers: IncomingHttpHeaders): string {
    // LINK-syeupoav: `decodeResponseBody` throws on a zero-byte body whenever a
    // `Content-Encoding` header is present, because it hands the empty buffer
    // to zlib. A 204, or an empty RDAP error body served with a stale encoding
    // header, must not surface as a decompression failure — so the empty case
    // is answered here instead of inheriting that defect. The fix to
    // `decompression.ts` itself belongs to LINK-syeupoav, not to this client.
    if (encoded.byteLength === 0) return "";
    try {
      const decoded = decodeResponseBody(
        encoded,
        headerLists(headers),
        this.policy.maxDecompressedBytes,
      );
      return Buffer.from(decoded).toString("utf8");
    } catch (error) {
      if (error instanceof DecompressedLimitError) {
        throw new RdapHttpFailure(
          "decompressed-response-too-large",
          String(this.policy.maxDecompressedBytes),
        );
      }
      if (error instanceof UnsupportedContentEncodingError) {
        throw new RdapHttpFailure("unsupported-content-encoding", error.encoding);
      }
      if (error instanceof ContentDecompressionError) {
        throw new RdapHttpFailure("decompression-error");
      }
      throw error;
    }
  }

  private requestHeaders(): Readonly<Record<string, string>> {
    // Node supplies `Host`. Nothing else is added: no Authorization, no cookie,
    // no referer, no ambient client identity.
    return {
      accept: RDAP_ACCEPT,
      "accept-encoding": RDAP_ACCEPT_ENCODING,
      ...(this.userAgent === null ? {} : { "user-agent": this.userAgent }),
    };
  }

  /**
   * A `dns.lookup` replacement that classifies every answer before handing any
   * of them back. Node calls it in one of two shapes depending on whether
   * happy-eyeballs family selection is active, so both are answered; either way
   * the set Node may connect to is the set that passed the policy.
   */
  private policedLookup(): LookupFunction {
    const classify = this.classify;
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
          callback(new RdapHttpFailure("dns-not-found", hostname), "");
          return;
        }
        for (const answer of answers) {
          const decision = classify(answer.address);
          if (!decision.allowed) {
            callback(
              new RdapHttpFailure(
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
}

/**
 * Parse the provider URL and refuse the shapes that must never reach a socket.
 * Userinfo is refused rather than dropped: a bootstrap entry carrying
 * credentials is a disclosure attempt, and the descriptor says there is no
 * credential to send.
 */
function providerUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RdapHttpFailure("invalid-url");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RdapHttpFailure("unsupported-scheme", url.protocol);
  }
  if (url.username !== "" || url.password !== "") {
    throw new RdapHttpFailure("url-credentials");
  }
  url.hash = "";
  return url;
}

/** Map a `node:http` client error onto the typed cause it represents. */
function requestFailure(error: unknown): unknown {
  // The lookup gate's refusal travels out through the socket's error channel.
  if (error instanceof RdapHttpFailure) return error;
  const code = systemErrorCode(error);
  switch (code) {
    case "ABORT_ERR":
      return new RdapHttpAbortError();
    case "ECONNREFUSED":
      return new RdapHttpFailure("connect-refused");
    case "ETIMEDOUT":
      return new RdapHttpFailure("connect-timeout");
    case "ENOTFOUND":
    case "ENODATA":
      return new RdapHttpFailure("dns-not-found");
    case "EAI_AGAIN":
    case "ETIMEOUT":
      return new RdapHttpFailure("dns-timeout");
    case "ECONNRESET":
    case "EPIPE":
      return new RdapHttpFailure("http-reset");
    case "HPE_HEADER_OVERFLOW":
      return new RdapHttpFailure("response-headers-too-large");
    default:
      if (isCertificateError(code)) return new RdapHttpFailure("tls-certificate");
      if (code !== null && code.startsWith("ERR_TLS")) return new RdapHttpFailure("tls-handshake");
      return new RdapHttpFailure("http-error");
  }
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
