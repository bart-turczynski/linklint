/**
 * RDAP registration-age source client types (LINK-okdrqxoz, M1a).
 *
 * M1a owns the source-client portion of the RDAP enrichment: IANA DNS bootstrap
 * routing, the domain query with redirect/throttle/cache handling, and response
 * normalization that preserves redacted or unsupported states as unknown. Age
 * computation and the conjunctive finding are M1b (LINK-brykoojd); nothing here
 * scores a verdict.
 */

/** Minimal provider-scoped HTTP client. RDAP endpoints are provider services,
 * not inspected destinations, so they do not pass through the L0 destination
 * boundary; callers inject a deterministic client in tests and a bounded Node
 * client in production. */
export interface RdapHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  /** Decoded response body text (RDAP responses are JSON). */
  readonly body: string;
}

/**
 * Conditional-refresh validators echoed back to a provider so it can answer
 * `304 Not Modified`.
 *
 * Deliberately NOT a free-form header map. An open `headers` field on a
 * provider request is a smuggling seam: the RDAP descriptor declares
 * `credentials: { kind: "none" }`, and a caller (or a poisoned options object)
 * could otherwise slip an `Authorization` or `Cookie` header into a request the
 * contract says carries no credential. Two named validators can carry nothing
 * else.
 */
export interface RdapConditionalRequest {
  /** Previous `ETag`, sent as `If-None-Match`. */
  readonly ifNoneMatch?: string;
  /** Previous `Last-Modified`, sent as `If-Modified-Since`. */
  readonly ifModifiedSince?: string;
}

export interface RdapHttpRequest {
  readonly url: string;
  /** Optional conditional-refresh validators. Absent on ordinary domain queries. */
  readonly conditional?: RdapConditionalRequest;
  readonly signal?: AbortSignal;
}

export interface RdapHttpClient {
  request(request: RdapHttpRequest): Promise<RdapHttpResponse>;
}

/** A monotonic-enough observation clock; injected for deterministic fixtures. */
export interface RdapClock {
  now(): Date;
}

/** The IANA DNS bootstrap registry (RFC 9224): TLD → authoritative RDAP base URLs. */
export interface RdapBootstrapRegistry {
  readonly version: string;
  readonly publication: string;
  /** Each service is `[ [tld, ...], [baseUrl, ...] ]`. */
  readonly services: readonly (readonly [readonly string[], readonly string[]])[];
}

/** Result of routing a registrable domain to an authoritative RDAP base URL. */
export type RdapRouting =
  | { readonly status: "routed"; readonly baseUrl: string; readonly tld: string }
  | { readonly status: "unsupported-tld"; readonly tld: string };

/**
 * Freshness and conditional-refresh metadata for a stored bootstrap registry
 * (LINK-mkddydzr). {@link RdapBootstrapRegistry} is the IANA document's own
 * shape and carries no freshness at all, so a caller holding one cannot tell a
 * registry downloaded an hour ago from one downloaded in 2019. This envelope is
 * what makes "the routing table is too old to trust" an answerable question.
 *
 * Holds no credential — the IANA bootstrap endpoint takes none.
 */
export interface RdapBootstrapSnapshotMetadata {
  /** Stable source identity of the acquisition path. */
  readonly source: string;
  /** Adapter/snapshot format version. */
  readonly version: string;
  /** Provider `ETag`, echoed as `If-None-Match` on refresh, or `null`. */
  readonly etag: string | null;
  /** Provider `Last-Modified`, echoed as `If-Modified-Since` on refresh, or `null`. */
  readonly lastModified: string | null;
  /** ISO-8601 instant this registry was downloaded. */
  readonly observedAt: string;
  /** ISO-8601 cadence expiry derived from the configured refresh interval, or `null`. */
  readonly expiresAt: string | null;
  /** The `version` field IANA published in the document itself. */
  readonly registryVersion: string;
  /** The `publication` instant IANA published in the document itself. */
  readonly registryPublication: string;
  /** Service entries retained after the base-URL scheme policy was applied. */
  readonly serviceCount: number;
  /**
   * Base URLs discarded by the scheme policy. Non-zero means some TLDs in the
   * published document route only over cleartext and are therefore reported as
   * `unsupported-tld` rather than queried — recorded so that is visible, not
   * silent.
   */
  readonly insecureBaseUrlsDropped: number;
}

/** A complete, JSON-safe bootstrap snapshot: freshness metadata plus the registry. */
export interface RdapBootstrapSnapshot {
  readonly metadata: RdapBootstrapSnapshotMetadata;
  readonly registry: RdapBootstrapRegistry;
}

/**
 * Caller-owned bootstrap store. The caller supplies the concrete storage
 * (directory, database, object store); this package ships the interface and no
 * filesystem implementation, because the IANA document is provider data the
 * caller owns and it is never bundled in the npm artifact.
 *
 * `replace` MUST swap the snapshot atomically, and the updater only ever calls
 * it with a fully-parsed registry, so a failed or malformed download leaves the
 * previous routing table intact.
 */
export interface RdapBootstrapStore {
  /** Current snapshot metadata for conditional refresh, or `null` when none is stored. */
  readMetadata(): Promise<RdapBootstrapSnapshotMetadata | null>;
  /** Atomically replace the stored bootstrap snapshot. */
  replace(snapshot: RdapBootstrapSnapshot): Promise<void>;
}

/** Machine-readable bootstrap-acquisition causes. Distinct from lookup causes. */
export type RdapBootstrapCauseCode =
  | "rdap-bootstrap-throttled"
  | "rdap-bootstrap-http-error"
  | "rdap-bootstrap-malformed"
  | "rdap-bootstrap-network-error"
  | "rdap-bootstrap-insecure-url"
  | "rdap-bootstrap-caller-aborted";

export interface RdapBootstrapCause {
  readonly code: RdapBootstrapCauseCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/**
 * Total outcome of one bootstrap update attempt.
 *
 * - `updated`: a new registry was parsed, policed and atomically written.
 * - `unchanged`: IANA reported no change (HTTP 304) or the stored snapshot is
 *   still within the refresh cadence; the store is untouched.
 * - `skipped`: throttling or cancellation prevented completion (retry later).
 * - `failure`: an HTTP error, network error, refused URL, or malformed
 *   document; the store is left untouched.
 */
export type RdapBootstrapUpdateResult =
  | { readonly status: "updated"; readonly snapshot: RdapBootstrapSnapshot }
  | {
      readonly status: "unchanged";
      readonly metadata: RdapBootstrapSnapshotMetadata;
      /** Why no download happened: the provider had no change, or the cadence guard. */
      readonly reason: "not-modified" | "within-cadence";
    }
  | { readonly status: "skipped"; readonly cause: RdapBootstrapCause }
  | { readonly status: "failure"; readonly cause: RdapBootstrapCause };

export interface UpdateRdapBootstrapOptions {
  /** Provider-scoped HTTP client; `createNodeRdapHttpClient` in production. */
  readonly client: RdapHttpClient;
  readonly store: RdapBootstrapStore;
  readonly clock: RdapClock;
  /** Bootstrap endpoint. Defaults to {@link IANA_RDAP_BOOTSTRAP_URL}. */
  readonly bootstrapUrl?: string;
  /**
   * Refresh cadence, in ms. Drives the snapshot's `expiresAt` and a pre-network
   * cadence guard: a stored snapshot observed more recently than this
   * short-circuits to `unchanged` without contacting IANA.
   *
   * Unlike the BYOK mirrors, this DEFAULTS to
   * {@link DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS} rather than to "disabled". IANA
   * serves the bootstrap registry free and unauthenticated, so an accidentally
   * unbounded refresh loop is a fair-use problem with no credential to rate-limit
   * it. Pass a non-positive value to disable the guard and expiry deliberately.
   */
  readonly cadenceMs?: number;
  /**
   * Allow a non-HTTPS `bootstrapUrl`. Default `false`: the routing table for
   * every RDAP query must not be fetched over a channel an on-path attacker can
   * rewrite. This exists so a hermetic loopback test can serve the document; it
   * is a test seam, not a production mode.
   */
  readonly allowInsecureBootstrapUrl?: boolean;
  /**
   * Keep non-HTTPS RDAP base URLs published in the document. Default `false`:
   * cleartext base URLs are dropped, and a TLD left with no base URL routes to
   * `unsupported-tld` — an explicit unsupported state, never a cleartext query.
   */
  readonly allowInsecureRdapBases?: boolean;
  readonly signal?: AbortSignal;
}

/** Machine-readable RDAP client causes. Distinct from framework degradation codes. */
export type RdapCauseCode =
  | "rdap-unsupported-tld"
  | "rdap-throttled"
  | "rdap-http-error"
  | "rdap-malformed"
  | "rdap-too-many-redirects"
  | "rdap-invalid-domain"
  | "rdap-network-error"
  | "rdap-caller-aborted";

export interface RdapCause {
  readonly code: RdapCauseCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/** A normalized RDAP domain record. Every absent or redacted field is `null`. */
export interface RdapDomainRecord {
  /** The A-label (LDH) domain that was queried. */
  readonly domain: string;
  readonly ldhName: string | null;
  readonly unicodeName: string | null;
  /** ISO-8601 registration instant, or `null` when absent/redacted. */
  readonly registrationDate: string | null;
  readonly lastChangedDate: string | null;
  readonly expirationDate: string | null;
  readonly registrar: { readonly name: string | null; readonly handle: string | null } | null;
  readonly nameservers: readonly string[];
  /** DNSSEC delegation state, or `null` when the source omits secureDNS. */
  readonly delegationSigned: boolean | null;
  readonly statuses: readonly string[];
  /** Redacted field names/reasons declared by the response (RFC 9537), if any. */
  readonly redacted: readonly string[];
  /** ISO-8601 observation instant. */
  readonly observedAt: string;
  /** ISO-8601 cache expiry derived from the configured TTL, or `null`. */
  readonly expiresAt: string | null;
}

/** Total outcome of a single RDAP domain lookup. */
export type RdapFetchResult =
  | { readonly status: "found"; readonly record: RdapDomainRecord; readonly fromCache: boolean }
  /** A completed query with no registration match (HTTP 404). Never a safety claim. */
  | { readonly status: "no-hit"; readonly domain: string }
  /** Authorization/policy/capacity/cancellation prevented completion. */
  | { readonly status: "skipped"; readonly cause: RdapCause }
  /** An attempted operation failed or returned an invalid contract. */
  | { readonly status: "failure"; readonly cause: RdapCause };

/** Read-through record cache keyed on the A-label domain. Expiry is enforced by the client. */
export interface RdapCache {
  get(key: string): RdapDomainRecord | undefined;
  set(key: string, record: RdapDomainRecord): void;
}

export interface FetchRdapDomainOptions {
  readonly client: RdapHttpClient;
  readonly registry: RdapBootstrapRegistry;
  /** The registrable domain to query; IDN input is converted to its A-label. */
  readonly registrableDomain: string;
  readonly clock: RdapClock;
  /** Record lifetime, in ms, used to derive `expiresAt`. Non-positive disables expiry. */
  readonly cacheTtlMs?: number;
  /** Optional read-through cache; a fresh entry short-circuits the network. */
  readonly cache?: RdapCache;
  /** Maximum RDAP redirects to follow. Bounded by a hard implementation cap. */
  readonly maxRedirects?: number;
  readonly signal?: AbortSignal;
}
