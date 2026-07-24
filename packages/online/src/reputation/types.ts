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

export interface RdapHttpRequest {
  readonly url: string;
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
