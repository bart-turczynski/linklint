/**
 * RDAP domain lookup client (LINK-okdrqxoz, M1a).
 *
 * Composes bootstrap routing, a read-through record cache, a bounded RDAP
 * redirect chain, and response normalization into one total lookup. Every branch
 * resolves to an explicit {@link RdapFetchResult}: `found`, `no-hit` (404, never
 * a safety claim), `skipped` (throttle, unsupported TLD, cancellation), or
 * `failure` (HTTP error, malformed body, redirect loop). It performs no scoring.
 *
 * RDAP servers are provider services, not inspected destinations, so this client
 * does not pass through the L0 destination boundary. It also never sends any
 * credential — RDAP domain queries are unauthenticated and disclose only the
 * registrable domain.
 */

import { domainToASCII } from "node:url";

import { resolveRdapBase } from "./rdap-bootstrap.js";
import { normalizeRdapDomain } from "./rdap-normalize.js";
import type {
  FetchRdapDomainOptions,
  RdapCause,
  RdapCauseCode,
  RdapDomainRecord,
  RdapFetchResult,
  RdapHttpResponse,
} from "./types.js";

export const RDAP_SOURCE_ID = "rdap.registration-age" as const;
export const RDAP_SOURCE_VERSION = "1.0.0" as const;
export const DEFAULT_RDAP_MAX_REDIRECTS = 3;
const MAX_RDAP_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Perform one RDAP domain lookup for a registrable domain. Reuses a fresh cached
 * record when a cache is supplied and its entry has not expired.
 */
export async function fetchRdapDomain(
  options: FetchRdapDomainOptions,
): Promise<RdapFetchResult> {
  const { client, registry, clock, cache, signal } = options;

  if (signal?.aborted) return skip("rdap-caller-aborted", "lookup cancelled before start");

  const aLabel = toALabel(options.registrableDomain);
  if (aLabel === null) {
    return skip("rdap-invalid-domain", `not a routable domain: ${options.registrableDomain}`);
  }

  // Read-through cache: a still-fresh record short-circuits the network.
  const cached = cache?.get(aLabel);
  if (cached && isFresh(cached, clock)) {
    return { status: "found", record: cached, fromCache: true };
  }

  const routing = resolveRdapBase(registry, aLabel);
  if (routing.status === "unsupported-tld") {
    return skip("rdap-unsupported-tld", `no RDAP service for .${routing.tld}`, false, {
      tld: routing.tld,
    });
  }

  const maxRedirects = boundedRedirects(options.maxRedirects);
  let url = `${routing.baseUrl}domain/${aLabel}`;
  const seen = new Set<string>();

  for (let redirect = 0; redirect <= maxRedirects; redirect++) {
    if (signal?.aborted) return skip("rdap-caller-aborted", "lookup cancelled");
    if (seen.has(url)) {
      return fail("rdap-too-many-redirects", `redirect loop at ${url}`);
    }
    seen.add(url);

    let response: RdapHttpResponse;
    try {
      response = await client.request(signal ? { url, signal } : { url });
    } catch (error) {
      if (signal?.aborted) return skip("rdap-caller-aborted", "lookup cancelled");
      return fail("rdap-network-error", describeError(error));
    }

    if (REDIRECT_STATUSES.has(response.status)) {
      const location = locationHeader(response.headers);
      if (location === null) return fail("rdap-http-error", `redirect without Location from ${url}`);
      url = resolveLocation(url, location);
      continue;
    }

    return terminalResult(response, aLabel, options);
  }

  return fail("rdap-too-many-redirects", `exceeded ${maxRedirects} redirects`);
}

/** Map a terminal (non-redirect) HTTP response to a result. */
function terminalResult(
  response: RdapHttpResponse,
  aLabel: string,
  options: FetchRdapDomainOptions,
): RdapFetchResult {
  const { clock, cache } = options;

  if (response.status === 404) return { status: "no-hit", domain: aLabel };
  if (response.status === 429) {
    return skip("rdap-throttled", "RDAP endpoint returned 429", true, {
      retryAfter: retryAfter(response),
    });
  }
  if (response.status < 200 || response.status >= 300) {
    return fail("rdap-http-error", `RDAP status ${response.status}`, { status: response.status });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    return fail("rdap-malformed", "RDAP response body is not valid JSON");
  }

  const observedAt = clock.now();
  const ttlMs = options.cacheTtlMs ?? 0;
  const expiresAt =
    Number.isFinite(ttlMs) && ttlMs > 0
      ? new Date(observedAt.getTime() + ttlMs).toISOString()
      : null;

  const record: RdapDomainRecord = normalizeRdapDomain(parsed, {
    domain: aLabel,
    observedAt: observedAt.toISOString(),
    expiresAt,
  });
  cache?.set(aLabel, record);
  return { status: "found", record, fromCache: false };
}

/** Convert a possibly-IDN domain to its A-label form, or `null` when unroutable. */
function toALabel(domain: string): string | null {
  if (typeof domain !== "string" || domain.trim() === "") return null;
  const trimmed = domain.trim().replace(/\.+$/, "").toLowerCase();
  const ascii = domainToASCII(trimmed);
  if (ascii === "" || !ascii.includes(".")) return null;
  return ascii;
}

function isFresh(record: RdapDomainRecord, clock: { now(): Date }): boolean {
  if (record.expiresAt === null) return false;
  const expiry = Date.parse(record.expiresAt);
  return Number.isFinite(expiry) && clock.now().getTime() < expiry;
}

function boundedRedirects(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    return DEFAULT_RDAP_MAX_REDIRECTS;
  }
  return Math.min(value, MAX_RDAP_REDIRECTS);
}

function locationHeader(headers: Readonly<Record<string, string>>): string | null {
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === "location" && value.trim() !== "") return value;
  }
  return null;
}

function resolveLocation(base: string, location: string): string {
  try {
    return new URL(location, base).toString();
  } catch {
    return location;
  }
}

function retryAfter(response: RdapHttpResponse): string | null {
  for (const [name, value] of Object.entries(response.headers)) {
    if (name.toLowerCase() === "retry-after") return value;
  }
  return null;
}

function describeError(error: unknown): string {
  return error instanceof Error ? `RDAP request failed: ${error.name}` : "RDAP request failed";
}

function skip(
  code: RdapCauseCode,
  message: string,
  retryable = false,
  details?: RdapCause["details"],
): RdapFetchResult {
  return { status: "skipped", cause: cause(code, message, retryable, details) };
}

function fail(
  code: RdapCauseCode,
  message: string,
  details?: RdapCause["details"],
): RdapFetchResult {
  return { status: "failure", cause: cause(code, message, false, details) };
}

function cause(
  code: RdapCauseCode,
  message: string,
  retryable: boolean,
  details?: RdapCause["details"],
): RdapCause {
  return details === undefined
    ? { code, message, retryable }
    : { code, message, retryable, details };
}
