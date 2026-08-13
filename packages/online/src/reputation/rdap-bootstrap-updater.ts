/**
 * IANA RDAP bootstrap acquisition (LINK-mkddydzr, sub-unit B).
 *
 * `parseRdapBootstrap` has always known how to READ the IANA registry, and
 * `createRdapAgeEnricher` has always REQUIRED one, but nothing in the package
 * ever fetched it. Every caller was left to obtain
 * `https://data.iana.org/rdap/dns.json` themselves and to invent their own
 * answer to "is this routing table still current?". This is that acquisition
 * path.
 *
 * SHAPE. Deliberately the caller-owned mirror/updater shape already established
 * by `mirrors/urlhaus-updater.ts` and `mirrors/phishtank-updater.ts`: a free
 * function over one options object, an injected async store the caller owns, an
 * abort pre-check, a cadence guard before any network, conditional refresh,
 * parse-before-write, and honest freshness metadata. A third bespoke shape for
 * the same job would be a third set of bugs.
 *
 * NO CREDENTIAL. This is the one structural difference from the BYOK mirrors.
 * URLhaus reveals an Auth-Key into a request header and PhishTank into the URL
 * path; IANA authenticates nothing. There is therefore no `credential` option
 * at all — not an optional one — so there is no slot a secret could be placed
 * into and no code path that could leak one.
 *
 * FAIR USE. IANA serves this document free and unauthenticated, which means
 * there is no key for them to throttle and no bill to notice. The cadence guard
 * therefore DEFAULTS on ({@link DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS}) rather than
 * defaulting off the way the credentialed mirrors' guards do; disabling it takes
 * an explicit non-positive `cadenceMs`.
 *
 * SCHEME POLICY (this layer owns it). `createNodeRdapHttpClient` accepts both
 * `http:` and `https:` and deliberately deferred the choice to here, so here it
 * is, in two parts:
 *
 *   1. The bootstrap document itself must be fetched over HTTPS. It is the
 *      routing table for every subsequent RDAP query, so an on-path attacker who
 *      can rewrite it can redirect every domain lookup at once. A non-HTTPS
 *      `bootstrapUrl` is refused with `rdap-bootstrap-insecure-url` unless the
 *      caller sets `allowInsecureBootstrapUrl` — which exists so a hermetic
 *      loopback test can serve the document, and is documented as a test seam.
 *   2. Base URLs published inside the document are filtered to HTTPS before the
 *      registry is stored. `resolveRdapBase` prefers HTTPS but falls back to the
 *      first URL, so an entry offering ONLY `http://` would otherwise silently
 *      produce cleartext RDAP queries. A TLD whose base URLs are all cleartext
 *      is dropped from the stored registry, which makes `resolveRdapBase` report
 *      `unsupported-tld` for it — the explicit unsupported state the module
 *      already defines, rather than a downgraded query. The count of dropped
 *      URLs is recorded in the snapshot metadata so the trade is visible.
 *      `allowInsecureRdapBases` opts back in.
 *
 * NEVER BUNDLED. No `dns.json` is committed, fixtured, or shipped: the document
 * is provider data the caller downloads and owns, exactly as
 * `docs/online-runtime-boundary.md` requires of feed snapshots. This module
 * ships the store INTERFACE and no filesystem implementation for the same
 * reason — the caller owns the directory or database.
 *
 * NOT A SEPARATE SOURCE. `data.iana.org` is a second provider connection, but it
 * emits no evidence and discloses nothing about the inspected subject: it
 * downloads the whole registry regardless of what is being checked. It therefore
 * gets no `OnlineSourceDescriptor` of its own — `assertValidSourceDescriptor`
 * requires a non-empty `evidenceScope`, and naming an evidence type nothing ever
 * emits would be a false declaration. This mirrors the URLhaus precedent, where
 * the dump download likewise has no descriptor separate from the source it feeds.
 *
 * No network I/O happens at import time; only a call to
 * {@link updateRdapBootstrap} contacts anything.
 */

import { parseRdapBootstrap } from "./rdap-bootstrap.js";
import type {
  RdapBootstrapCause,
  RdapBootstrapCauseCode,
  RdapBootstrapRegistry,
  RdapBootstrapSnapshot,
  RdapBootstrapSnapshotMetadata,
  RdapBootstrapUpdateResult,
  RdapConditionalRequest,
  RdapHttpResponse,
  UpdateRdapBootstrapOptions,
} from "./types.js";

/** The IANA DNS bootstrap registry endpoint (RFC 9224 §4). */
export const IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json" as const;

/** Stable identity recorded in a stored snapshot's metadata. */
export const RDAP_BOOTSTRAP_SOURCE_ID = "iana.rdap-bootstrap" as const;
export const RDAP_BOOTSTRAP_SOURCE_VERSION = "1.0.0" as const;

/**
 * Default refresh cadence: 24h. The registry changes on the order of new TLD
 * delegations, so a day is generous for correctness and restrained for a free
 * public service.
 */
export const DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS = 86_400_000;

/**
 * Refresh a caller-owned IANA bootstrap snapshot. Reuses the stored snapshot
 * when it is still within the refresh cadence or when IANA reports no change.
 */
export async function updateRdapBootstrap(
  options: UpdateRdapBootstrapOptions,
): Promise<RdapBootstrapUpdateResult> {
  const { client, store, clock, signal } = options;

  if (signal?.aborted) {
    return skip("rdap-bootstrap-caller-aborted", "update cancelled before start");
  }

  const previous = await store.readMetadata();
  const now = clock.now();
  const cadenceMs = resolveCadence(options.cadenceMs);

  // Cadence guard: the fair-use gate. A snapshot still inside its window is
  // answered without a request reaching IANA at all.
  if (previous !== null && cadenceMs !== null && withinCadence(previous, now, cadenceMs)) {
    return { status: "unchanged", metadata: previous, reason: "within-cadence" };
  }

  const url = options.bootstrapUrl ?? IANA_RDAP_BOOTSTRAP_URL;
  const urlRefusal = refuseInsecureUrl(url, options.allowInsecureBootstrapUrl === true);
  if (urlRefusal !== null) return urlRefusal;

  const conditional = conditionalValidators(previous);
  let response: RdapHttpResponse;
  try {
    response = await client.request({
      url,
      ...(conditional === null ? {} : { conditional }),
      ...(signal ? { signal } : {}),
    });
  } catch (error) {
    if (signal?.aborted || isAbortError(error)) {
      return skip("rdap-bootstrap-caller-aborted", "update cancelled");
    }
    return fail("rdap-bootstrap-network-error", describeError(error), transportDetail(error));
  }

  if (response.status === 304) {
    if (previous !== null) {
      return { status: "unchanged", metadata: previous, reason: "not-modified" };
    }
    // A 304 without a stored snapshot is a provider/contract violation: nothing
    // was sent to condition on, so there is nothing to reuse.
    return fail("rdap-bootstrap-http-error", "provider returned 304 with no stored snapshot");
  }

  if (response.status === 429) {
    return skip("rdap-bootstrap-throttled", "IANA bootstrap endpoint returned 429", true, {
      retryAfter: headerValue(response, "retry-after"),
    });
  }

  if (response.status < 200 || response.status >= 300) {
    return fail("rdap-bootstrap-http-error", `IANA bootstrap status ${response.status}`, {
      status: response.status,
    });
  }

  // Parse before write. A truncated, HTML-error-page, or otherwise malformed
  // body must never replace a good routing table.
  const parsed = parseBootstrapDocument(response.body);
  if (parsed === null) {
    return fail(
      "rdap-bootstrap-malformed",
      "IANA bootstrap body is not a valid RFC 9224 registry document",
    );
  }

  const policed = applyBaseUrlSchemePolicy(parsed, options.allowInsecureRdapBases === true);
  const expiresAt =
    cadenceMs !== null ? new Date(now.getTime() + cadenceMs).toISOString() : null;
  const metadata: RdapBootstrapSnapshotMetadata = {
    source: RDAP_BOOTSTRAP_SOURCE_ID,
    version: RDAP_BOOTSTRAP_SOURCE_VERSION,
    etag: headerValue(response, "etag"),
    lastModified: headerValue(response, "last-modified"),
    observedAt: now.toISOString(),
    expiresAt,
    registryVersion: policed.registry.version,
    registryPublication: policed.registry.publication,
    serviceCount: policed.registry.services.length,
    insecureBaseUrlsDropped: policed.dropped,
  };
  const snapshot: RdapBootstrapSnapshot = { metadata, registry: policed.registry };

  await store.replace(snapshot);
  return { status: "updated", snapshot };
}

/**
 * Apply the base-URL scheme policy to a freshly parsed registry.
 *
 * Under the default (strict) policy a service keeps only its HTTPS base URLs; a
 * service left with none is removed entirely, so its TLDs resolve to
 * `unsupported-tld` instead of being queried in cleartext.
 */
function applyBaseUrlSchemePolicy(
  registry: RdapBootstrapRegistry,
  allowInsecure: boolean,
): { readonly registry: RdapBootstrapRegistry; readonly dropped: number } {
  if (allowInsecure) return { registry, dropped: 0 };

  let dropped = 0;
  const services: (readonly [readonly string[], readonly string[]])[] = [];
  for (const [tlds, urls] of registry.services) {
    const secure = urls.filter((url) => url.toLowerCase().startsWith("https://"));
    dropped += urls.length - secure.length;
    if (secure.length > 0) services.push([tlds, secure]);
  }
  return {
    registry: { version: registry.version, publication: registry.publication, services },
    dropped,
  };
}

/** Decode the response body as JSON, then validate it as an RFC 9224 registry. */
function parseBootstrapDocument(body: string): RdapBootstrapRegistry | null {
  let decoded: unknown;
  try {
    decoded = JSON.parse(body);
  } catch {
    return null;
  }
  return parseRdapBootstrap(decoded);
}

/**
 * Refuse a bootstrap URL the scheme policy does not allow. Returns `null` when
 * the URL is acceptable.
 */
function refuseInsecureUrl(
  raw: string,
  allowInsecure: boolean,
): RdapBootstrapUpdateResult | null {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return fail("rdap-bootstrap-insecure-url", "bootstrapUrl is not a valid absolute URL");
  }
  if (parsed.protocol === "https:") return null;
  if (parsed.protocol === "http:" && allowInsecure) return null;
  return fail(
    "rdap-bootstrap-insecure-url",
    "bootstrapUrl must use https (set allowInsecureBootstrapUrl to override)",
    { scheme: parsed.protocol },
  );
}

/** Build conditional-refresh validators from the previous snapshot. */
function conditionalValidators(
  previous: RdapBootstrapSnapshotMetadata | null,
): RdapConditionalRequest | null {
  if (previous === null) return null;
  const conditional: { ifNoneMatch?: string; ifModifiedSince?: string } = {};
  if (previous.etag !== null) conditional.ifNoneMatch = previous.etag;
  if (previous.lastModified !== null) conditional.ifModifiedSince = previous.lastModified;
  return conditional.ifNoneMatch === undefined && conditional.ifModifiedSince === undefined
    ? null
    : conditional;
}

function withinCadence(
  previous: RdapBootstrapSnapshotMetadata,
  now: Date,
  cadenceMs: number,
): boolean {
  const observed = Date.parse(previous.observedAt);
  return Number.isFinite(observed) && now.getTime() < observed + cadenceMs;
}

/** Absent means the default cadence; a non-positive value disables it explicitly. */
function resolveCadence(value: number | undefined): number | null {
  if (value === undefined) return DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS;
  return Number.isFinite(value) && value > 0 ? value : null;
}

function headerValue(response: RdapHttpResponse, name: string): string | null {
  for (const [key, value] of Object.entries(response.headers)) {
    if (key.toLowerCase() === name && value.trim() !== "") return value;
  }
  return null;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

/** The transport's typed cause code, when the client supplied one. Never body content. */
function transportDetail(error: unknown): RdapBootstrapCause["details"] | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? { transport: code } : undefined;
}

function describeError(error: unknown): string {
  return error instanceof Error
    ? `IANA bootstrap request failed: ${error.name}`
    : "IANA bootstrap request failed";
}

function skip(
  code: RdapBootstrapCauseCode,
  message: string,
  retryable = false,
  details?: RdapBootstrapCause["details"],
): RdapBootstrapUpdateResult {
  return { status: "skipped", cause: cause(code, message, retryable, details) };
}

function fail(
  code: RdapBootstrapCauseCode,
  message: string,
  details?: RdapBootstrapCause["details"],
): RdapBootstrapUpdateResult {
  return { status: "failure", cause: cause(code, message, false, details) };
}

function cause(
  code: RdapBootstrapCauseCode,
  message: string,
  retryable: boolean,
  details?: RdapBootstrapCause["details"],
): RdapBootstrapCause {
  return details === undefined
    ? { code, message, retryable }
    : { code, message, retryable, details };
}
