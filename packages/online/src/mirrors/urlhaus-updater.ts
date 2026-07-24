/**
 * URLhaus Auth-Key dump updater (LINK-qzybihpz, M4a).
 *
 * Downloads the URLhaus Community API export with a caller-owned Auth-Key into a
 * caller-owned snapshot store. One call resolves to an explicit
 * {@link UrlhausUpdateResult}: `updated`, `unchanged` (304 or within cadence),
 * `skipped` (throttle/cancellation), or `failure` (HTTP/network/malformed). It
 * performs no scoring and emits no evidence.
 *
 * Discipline enforced here:
 * - **Auth-Key safety**: the credential is revealed *only* into the `Auth-Key`
 *   request header, at the moment of the request, and into no other sink — not a
 *   cache key, snapshot, log line, error, or result.
 * - **Provider cadence + conditional refresh**: a stored snapshot still within
 *   `cadenceMs` short-circuits without a request; otherwise the previous
 *   `ETag`/`Last-Modified` are echoed so the provider can answer `304 Not
 *   Modified`.
 * - **Atomic replacement**: `store.replace` is called only with a fully-parsed
 *   snapshot, so a throttle, network error, or malformed dump never overwrites a
 *   good snapshot with a partial one.
 * - **Honest freshness**: every written snapshot records `observedAt`, a
 *   cadence-derived `expiresAt`, and the provider validators for the next refresh.
 *
 * URLhaus is a provider service, not an inspected destination, so this updater
 * does not pass through the L0 destination boundary.
 */

import { parseUrlhausCsv } from "./urlhaus-parse.js";
import {
  URLHAUS_ONLINE_DUMP_URL,
  URLHAUS_SOURCE_ID,
  URLHAUS_SOURCE_VERSION,
} from "./urlhaus-descriptor.js";
import type {
  UpdateUrlhausSnapshotOptions,
  UrlhausCause,
  UrlhausCauseCode,
  UrlhausHttpResponse,
  UrlhausSnapshot,
  UrlhausSnapshotMetadata,
  UrlhausUpdateResult,
} from "./types.js";

/** The provider header carrying the caller-owned Auth-Key. */
const AUTH_KEY_HEADER = "Auth-Key";

/**
 * Refresh a caller-owned URLhaus snapshot. Reuses the stored snapshot when it is
 * still within the refresh cadence or when the provider reports no change.
 */
export async function updateUrlhausSnapshot(
  options: UpdateUrlhausSnapshotOptions,
): Promise<UrlhausUpdateResult> {
  const { client, store, credential, clock, signal } = options;

  if (signal?.aborted) {
    return skip("urlhaus-caller-aborted", "update cancelled before start");
  }

  const previous = await store.readMetadata();
  const now = clock.now();
  const cadenceMs = positiveMs(options.cadenceMs);

  // Cadence guard: honor the provider's refresh cadence and fair use by not
  // re-downloading a snapshot that is still within its window.
  if (previous !== null && cadenceMs !== null && withinCadence(previous, now, cadenceMs)) {
    return { status: "unchanged", metadata: previous, reason: "within-cadence" };
  }

  const url = options.dumpUrl ?? URLHAUS_ONLINE_DUMP_URL;
  const headers: Record<string, string> = {
    // Reveal the credential only here, into the provider authorization header.
    [AUTH_KEY_HEADER]: credential.reveal(),
    ...conditionalHeaders(previous),
  };

  let response: UrlhausHttpResponse;
  try {
    response = await client.request(signal ? { url, headers, signal } : { url, headers });
  } catch (error) {
    if (signal?.aborted) return skip("urlhaus-caller-aborted", "update cancelled");
    return fail("urlhaus-network-error", describeError(error));
  }

  if (response.status === 304) {
    if (previous !== null) {
      return { status: "unchanged", metadata: previous, reason: "not-modified" };
    }
    // A 304 without a stored snapshot is a provider/contract violation.
    return fail("urlhaus-http-error", "provider returned 304 with no stored snapshot");
  }

  if (response.status === 429) {
    return skip("urlhaus-throttled", "URLhaus endpoint returned 429", true, {
      retryAfter: retryAfter(response),
    });
  }

  if (response.status < 200 || response.status >= 300) {
    return fail("urlhaus-http-error", `URLhaus status ${response.status}`, {
      status: response.status,
    });
  }

  const parsed = parseUrlhausCsv(response.body);
  if (parsed === null) {
    return fail("urlhaus-malformed", "URLhaus response body is not a recognizable CSV dump");
  }

  const expiresAt =
    cadenceMs !== null ? new Date(now.getTime() + cadenceMs).toISOString() : null;
  const metadata: UrlhausSnapshotMetadata = {
    source: URLHAUS_SOURCE_ID,
    version: URLHAUS_SOURCE_VERSION,
    etag: headerValue(response, "etag"),
    lastModified: headerValue(response, "last-modified"),
    observedAt: now.toISOString(),
    expiresAt,
    recordCount: parsed.records.length,
  };
  const snapshot: UrlhausSnapshot = { metadata, records: parsed.records };

  await store.replace(snapshot);
  return { status: "updated", snapshot };
}

/** Build conditional-refresh headers from the previous snapshot's validators. */
function conditionalHeaders(
  previous: UrlhausSnapshotMetadata | null,
): Record<string, string> {
  if (previous === null) return {};
  const headers: Record<string, string> = {};
  if (previous.etag !== null) headers["If-None-Match"] = previous.etag;
  if (previous.lastModified !== null) headers["If-Modified-Since"] = previous.lastModified;
  return headers;
}

function withinCadence(
  previous: UrlhausSnapshotMetadata,
  now: Date,
  cadenceMs: number,
): boolean {
  const observed = Date.parse(previous.observedAt);
  return Number.isFinite(observed) && now.getTime() < observed + cadenceMs;
}

function positiveMs(value: number | undefined): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function headerValue(response: UrlhausHttpResponse, name: string): string | null {
  for (const [key, value] of Object.entries(response.headers)) {
    if (key.toLowerCase() === name && value.trim() !== "") return value;
  }
  return null;
}

function retryAfter(response: UrlhausHttpResponse): string | null {
  return headerValue(response, "retry-after");
}

function describeError(error: unknown): string {
  return error instanceof Error ? `URLhaus request failed: ${error.name}` : "URLhaus request failed";
}

function skip(
  code: UrlhausCauseCode,
  message: string,
  retryable = false,
  details?: UrlhausCause["details"],
): UrlhausUpdateResult {
  return { status: "skipped", cause: cause(code, message, retryable, details) };
}

function fail(
  code: UrlhausCauseCode,
  message: string,
  details?: UrlhausCause["details"],
): UrlhausUpdateResult {
  return { status: "failure", cause: cause(code, message, false, details) };
}

function cause(
  code: UrlhausCauseCode,
  message: string,
  retryable: boolean,
  details?: UrlhausCause["details"],
): UrlhausCause {
  return details === undefined
    ? { code, message, retryable }
    : { code, message, retryable, details };
}
