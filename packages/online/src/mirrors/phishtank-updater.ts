/**
 * PhishTank app-key feed updater (LINK-lddpffio, M5a).
 *
 * Downloads the PhishTank online-valid CSV feed with a caller-owned application
 * key into a caller-owned snapshot store. One call resolves to an explicit
 * {@link PhishTankUpdateResult}: `updated`, `unchanged` (304 or within cadence),
 * `skipped` (throttle/cancellation), or `failure` (HTTP/network/malformed). It
 * performs no scoring and emits no evidence.
 *
 * Discipline enforced here:
 * - **App-key safety**: PhishTank keys go in the URL *path*. The key is revealed
 *   only when building the request URL, and that keyed URL is never stored in
 *   metadata, the result, evidence, or a cause.
 * - **Descriptive user agent**: PhishTank rejects generic agents; the caller's
 *   `User-Agent` is sent on every request.
 * - **Hourly cadence + conditional refresh**: a snapshot still within `cadenceMs`
 *   short-circuits without a request; otherwise the previous `ETag`/`Last-Modified`
 *   are echoed so the provider can answer `304 Not Modified`.
 * - **Rate limits**: `429` and `509` (bandwidth exceeded) become retryable skips.
 * - **Atomic replacement**: `store.replace` is called only with a fully-parsed
 *   snapshot, so a throttle, error, or malformed feed never overwrites a good one.
 *
 * PhishTank is a provider service, not an inspected destination, so this updater
 * does not pass through the L0 destination boundary.
 */

import { parsePhishTankCsv } from "./phishtank-parse.js";
import {
  PHISHTANK_DATA_BASE_URL,
  PHISHTANK_DEFAULT_CADENCE_MS,
  PHISHTANK_ONLINE_VALID_FEED,
  PHISHTANK_SOURCE_ID,
  PHISHTANK_SOURCE_VERSION,
} from "./phishtank-descriptor.js";
import type {
  PhishTankCause,
  PhishTankCauseCode,
  PhishTankHttpResponse,
  PhishTankSnapshot,
  PhishTankSnapshotMetadata,
  PhishTankUpdateResult,
  UpdatePhishTankSnapshotOptions,
} from "./phishtank-types.js";

/** Default descriptive user agent. Callers SHOULD override with their own identity. */
const DEFAULT_USER_AGENT = "linklint-phishtank-mirror";

/** HTTP statuses PhishTank uses to signal throttling / bandwidth limits. */
const THROTTLE_STATUSES = new Set([429, 509]);

/**
 * Refresh a caller-owned PhishTank snapshot. Reuses the stored snapshot when it is
 * still within the refresh cadence or when the provider reports no change.
 */
export async function updatePhishTankSnapshot(
  options: UpdatePhishTankSnapshotOptions,
): Promise<PhishTankUpdateResult> {
  const { client, store, appKey, clock, signal } = options;

  if (signal?.aborted) {
    return skip("phishtank-caller-aborted", "update cancelled before start");
  }

  const previous = await store.readMetadata();
  const now = clock.now();
  const cadenceMs = resolveCadence(options.cadenceMs);

  if (previous !== null && cadenceMs !== null && withinCadence(previous, now, cadenceMs)) {
    return { status: "unchanged", metadata: previous, reason: "within-cadence" };
  }

  // Reveal the key only here, into the download URL path. Never stored anywhere.
  const base = (options.baseUrl ?? PHISHTANK_DATA_BASE_URL).replace(/\/+$/, "");
  const url = `${base}/${appKey.reveal()}/${PHISHTANK_ONLINE_VALID_FEED}`;
  const headers: Record<string, string> = {
    "User-Agent": options.userAgent ?? DEFAULT_USER_AGENT,
    ...conditionalHeaders(previous),
  };

  let response: PhishTankHttpResponse;
  try {
    response = await client.request(signal ? { url, headers, signal } : { url, headers });
  } catch (error) {
    if (signal?.aborted) return skip("phishtank-caller-aborted", "update cancelled");
    return fail("phishtank-network-error", describeError(error));
  }

  if (response.status === 304) {
    if (previous !== null) {
      return { status: "unchanged", metadata: previous, reason: "not-modified" };
    }
    return fail("phishtank-http-error", "provider returned 304 with no stored snapshot");
  }

  if (THROTTLE_STATUSES.has(response.status)) {
    return skip("phishtank-throttled", `PhishTank endpoint returned ${response.status}`, true, {
      status: response.status,
      retryAfter: headerValue(response, "retry-after"),
    });
  }

  if (response.status < 200 || response.status >= 300) {
    return fail("phishtank-http-error", `PhishTank status ${response.status}`, {
      status: response.status,
    });
  }

  const parsed = parsePhishTankCsv(response.body);
  if (parsed === null) {
    return fail("phishtank-malformed", "PhishTank response body is not a recognizable CSV feed");
  }

  const expiresAt =
    cadenceMs !== null ? new Date(now.getTime() + cadenceMs).toISOString() : null;
  const metadata: PhishTankSnapshotMetadata = {
    source: PHISHTANK_SOURCE_ID,
    version: PHISHTANK_SOURCE_VERSION,
    etag: headerValue(response, "etag"),
    lastModified: headerValue(response, "last-modified"),
    observedAt: now.toISOString(),
    expiresAt,
    recordCount: parsed.records.length,
  };
  const snapshot: PhishTankSnapshot = { metadata, records: parsed.records };

  await store.replace(snapshot);
  return { status: "updated", snapshot };
}

function conditionalHeaders(
  previous: PhishTankSnapshotMetadata | null,
): Record<string, string> {
  if (previous === null) return {};
  const headers: Record<string, string> = {};
  if (previous.etag !== null) headers["If-None-Match"] = previous.etag;
  if (previous.lastModified !== null) headers["If-Modified-Since"] = previous.lastModified;
  return headers;
}

function withinCadence(
  previous: PhishTankSnapshotMetadata,
  now: Date,
  cadenceMs: number,
): boolean {
  const observed = Date.parse(previous.observedAt);
  return Number.isFinite(observed) && now.getTime() < observed + cadenceMs;
}

/** Resolve the cadence: an explicit non-positive value disables it; absent uses the hourly default. */
function resolveCadence(value: number | undefined): number | null {
  if (value === undefined) return PHISHTANK_DEFAULT_CADENCE_MS;
  return Number.isFinite(value) && value > 0 ? value : null;
}

function headerValue(response: PhishTankHttpResponse, name: string): string | null {
  for (const [key, value] of Object.entries(response.headers)) {
    if (key.toLowerCase() === name && value.trim() !== "") return value;
  }
  return null;
}

function describeError(error: unknown): string {
  return error instanceof Error
    ? `PhishTank request failed: ${error.name}`
    : "PhishTank request failed";
}

function skip(
  code: PhishTankCauseCode,
  message: string,
  retryable = false,
  details?: PhishTankCause["details"],
): PhishTankUpdateResult {
  return { status: "skipped", cause: cause(code, message, retryable, details) };
}

function fail(
  code: PhishTankCauseCode,
  message: string,
  details?: PhishTankCause["details"],
): PhishTankUpdateResult {
  return { status: "failure", cause: cause(code, message, false, details) };
}

function cause(
  code: PhishTankCauseCode,
  message: string,
  retryable: boolean,
  details?: PhishTankCause["details"],
): PhishTankCause {
  return details === undefined
    ? { code, message, retryable }
    : { code, message, retryable, details };
}
