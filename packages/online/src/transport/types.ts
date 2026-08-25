export type TransportProtocol = "http:" | "https:";
export type TransportMethod = "GET" | "HEAD";

export interface DnsAddress {
  readonly address: string;
  readonly family: 4 | 6;
  readonly ttlSeconds: number;
}

export interface ResolveRequest {
  readonly hostname: string;
  readonly signal?: AbortSignal;
}

export interface ResolverPort {
  resolve(request: ResolveRequest): Promise<readonly DnsAddress[]>;
}

export interface ConnectRequest {
  readonly protocol: TransportProtocol;
  readonly hostname: string;
  readonly address: string;
  readonly port: number;
  readonly serverName?: string;
  readonly signal?: AbortSignal;
}

export interface TransportConnection {
  readonly id: string;
  readonly protocol: TransportProtocol;
  /**
   * The peer address the socket OBSERVED, re-checked against the pinned
   * {@link ConnectRequest.address}. A port that cannot observe it must fail the
   * connect rather than echo the requested value: the check compares this field
   * with the pin, so a substituted pin would confirm itself (LINK-abozdqtp).
   */
  readonly remoteAddress: string;
  /** The peer port the socket OBSERVED, under the same rule as the address. */
  readonly remotePort: number;
  readonly tls?: {
    readonly authorized: boolean;
    readonly serverName: string;
    readonly peerDnsNames: readonly string[];
  };
}

export interface ConnectorPort {
  connect(request: ConnectRequest): Promise<TransportConnection>;
  close(connectionId: string): void | Promise<void>;
}

export interface HttpRequest {
  /**
   * The connection {@link ConnectorPort.connect} returned, whose address was
   * pinned before the connect and whose reported peer was checked against that
   * pin afterwards. An {@link HttpPort} must write this request onto THAT
   * connection and no other. {@link HttpResponse} carries a status, headers and
   * a body and nothing that identifies the socket they came off, so the
   * transport cannot re-check this binding the way it re-checks
   * {@link TransportConnection.remoteAddress} at connect time — the obligation
   * is the port's (LINK-zzaerxod).
   *
   * A port that ignores this field and re-resolves {@link HttpRequest.url}
   * instead — the shape a `fetch`- or `undici`-backed adapter falls into — sends
   * the request to whatever the runtime resolves at that moment, reopening the
   * DNS-rebinding window the pin exists to close.
   */
  readonly connectionId: string;
  readonly url: string;
  readonly method: TransportMethod;
  readonly headers: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, readonly string[]>>;
  readonly body: AsyncIterable<Uint8Array>;
}

/**
 * A trusted capability, not a sandboxed one. The transport's destination rules
 * stop at this seam — everything past it is the adapter's own conduct — so an
 * implementer takes on three obligations that nothing downstream can check
 * (LINK-zzaerxod):
 *
 * - use the connection named by {@link HttpRequest.connectionId} and no other,
 *   rather than re-resolving {@link HttpRequest.url};
 * - return a redirect response as-is. Following one skips the caller's per-hop
 *   authorization and the offline inspection of the new target behind it;
 * - send exactly {@link HttpRequest.headers} — no cookie jar, ambient
 *   credential, proxy authorization, or runtime default of the port's own.
 *
 * The built-in composition meets all three structurally rather than by
 * protocol: `NodeConnectionPorts` implements this interface and
 * {@link ConnectorPort} together and owns the socket map, and
 * `createNodeSafeTransport()` passes ONE instance as both, so the pinned socket
 * and the request written onto it are bound by object identity. See
 * `docs/safe-transport.md` and F6/F7 in `docs/guarantees.md`.
 */
export interface HttpPort {
  request(request: HttpRequest): Promise<HttpResponse>;
}

export interface ClockPort {
  now(): Date;
  sleep(delayMs: number, signal?: AbortSignal): Promise<void>;
}

export interface SafeTransportPorts {
  readonly resolver: ResolverPort;
  readonly connector: ConnectorPort;
  readonly http: HttpPort;
  readonly clock: ClockPort;
}

export interface DestinationFetchAuthorization {
  readonly kind: "destination-fetch";
  /** Must exactly match the request URL. Redirects require a new authorization. */
  readonly url: string;
}

export interface SafeFetchRequest {
  readonly url: string;
  readonly authorization: DestinationFetchAuthorization;
  readonly method?: TransportMethod;
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Dedicated synthetic-Referer channel and the only way a `Referer` reaches the
   * wire — `headers` never forwards one, so an ambient caller referrer is still
   * always stripped. The value must be an absolute `http(s)` URL, free of
   * userinfo, and same-origin with the request URL; anything else blocks the
   * request with `referer-not-same-origin` before any DNS or connection.
   */
  readonly sameOriginReferer?: string;
  readonly signal?: AbortSignal;
}

/**
 * Why a destination address was refused.
 *
 * The `ip_*` members come from core's classifier; the rest from this package's
 * supplemental table (`transport/address.ts`). Core is consulted FIRST, so a
 * range covered by both reports core's label.
 *
 * `benchmark` and `discard` are currently UNREACHABLE for that reason — since S3
 * core's IANA-derived table covers every range that would produce them. They are
 * retained because the supplemental rules behind them are a deliberate
 * fail-closed backstop, not because they can be observed today. Which layer
 * answers for each range is pinned in
 * `test/address-table-consistency.test.ts` (LINK-cmstadju), so this comment
 * cannot quietly go stale.
 */
export type TransportAddressCategory =
  | "ip_cloud_metadata"
  | "ip_loopback"
  | "ip_link_local"
  | "ip_private"
  | "ip_reserved"
  | "documentation"
  | "benchmark"
  | "discard"
  | "transition"
  | "invalid";

export interface TransportAddressDecision {
  readonly address: string;
  readonly family: 4 | 6 | null;
  readonly allowed: boolean;
  readonly category: TransportAddressCategory | null;
}

export type TransportCauseCode =
  | "authorization-required"
  | "invalid-url"
  | "unsupported-scheme"
  | "unsupported-method"
  | "url-credentials"
  | "referer-not-same-origin"
  | "prohibited-address"
  | "hop-limit"
  | "response-too-large"
  | "response-too-slow"
  | "decompressed-response-too-large"
  | "response-headers-too-large"
  | "unsupported-content-encoding"
  | "timeout"
  | "caller-aborted"
  | "dns-not-found"
  | "dns-timeout"
  | "dns-malformed"
  | "dns-error"
  | "connect-refused"
  | "connect-timeout"
  | "connect-error"
  | "connection-address-mismatch"
  | "tls-handshake"
  | "tls-certificate"
  | "http-malformed"
  | "http-reset"
  | "http-timeout"
  | "http-error"
  | "decompression-error";

export interface TransportCause {
  readonly code: TransportCauseCode;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

export interface TransportEvidence {
  readonly type: "transport.attempt";
  readonly subject: { readonly kind: "url"; readonly value: string };
  readonly observedAt: string;
  readonly hop: number;
  readonly protocol?: TransportProtocol;
  readonly hostname?: string;
  readonly port?: number;
  /**
   * The addresses the resolver returned for this hop — for the built-in resolver, one
   * `dns.lookup(hostname, { all: true, verbatim: true })`, not an authoritative A/AAAA
   * RRset. `selectedAddress` is always one of these (`LINK-rbghrpru`).
   */
  readonly resolvedAddresses?: readonly string[];
  readonly selectedAddress?: string;
}

export interface SafeFetchResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, readonly string[]>>;
  readonly body: Uint8Array;
  readonly encodedBytes: number;
  readonly decompressedBytes: number;
}

interface SafeFetchOutcomeBase {
  readonly subject: { readonly kind: "url"; readonly value: string };
  readonly observedAt: string;
  readonly evidence: TransportEvidence;
}

export interface SafeFetchSuccess extends SafeFetchOutcomeBase {
  readonly status: "success";
  readonly response: SafeFetchResponse;
}

export interface SafeFetchBlocked extends SafeFetchOutcomeBase {
  readonly status: "blocked";
  readonly cause: TransportCause;
}

export interface SafeFetchIncomplete extends SafeFetchOutcomeBase {
  readonly status: "incomplete";
  readonly cause: TransportCause;
}

export type SafeFetchOutcome = SafeFetchSuccess | SafeFetchBlocked | SafeFetchIncomplete;

export interface TransportBudgetUsage {
  readonly hops: number;
  readonly encodedBytes: number;
  readonly decompressedBytes: number;
  readonly elapsedMs: number;
}

export interface SafeTransportSession {
  readonly usage: TransportBudgetUsage;
  fetch(request: SafeFetchRequest): Promise<SafeFetchOutcome>;
}

export interface SafeTransport {
  createSession(): SafeTransportSession;
}
