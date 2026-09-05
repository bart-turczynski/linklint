/**
 * PhishTank feed updater (LINK-lddpffio, M5a; app key made optional by
 * LINK-plfzjlxg).
 *
 * Downloads the PhishTank online-valid CSV feed into a caller-owned snapshot
 * store. One call resolves to an explicit {@link PhishTankUpdateResult}:
 * `updated`, `unchanged` (304 or within cadence), `skipped`
 * (throttle/cancellation), or `failure` (HTTP/network/malformed). It performs no
 * scoring and emits no evidence.
 *
 * THE APP KEY IS OPTIONAL, BECAUSE PHISHTANK DOES NOT REQUIRE ONE. Measured
 * 2026-09-05: `https://data.phishtank.com/data/online-valid.csv` — no key in the
 * path — answers `302` to a signed CDN URL serving 74,539 verified-phish
 * records as `text/csv`. A syntactically plausible but fictional key in the key
 * position produces the identical redirect, so that path segment authenticates
 * nothing today. This updater previously demanded a key it could not use, which
 * meant an operator without one concluded the mirror was unavailable while the
 * data was freely reachable. A key is still honoured when supplied: PhishTank's
 * access policy has moved before, and a caller who has registered one should
 * keep sending it rather than be silently anonymised.
 *
 * THE HOP IS FOLLOWED BY THE SHIPPED CLIENT (LINK-scectgty). That `302` points
 * at `cdn.phishtank.com`, a host the caller did not name, and for a while
 * `mirror-http-node.ts` followed no redirect at all — so
 * `createNodePhishTankHttpClient` turned the live feed into
 * `phishtank-http-error` / `PhishTank status 302` whether or not a key was
 * configured, and making the key optional (LINK-plfzjlxg) removed a false
 * precondition without making the default download succeed.
 *
 * It succeeds now. The engine follows a bounded chain — three hops, HTTPS only,
 * every hop address-classified — and DROPS every caller header but
 * `Accept`, `Accept-Encoding` and `User-Agent` when the origin changes, which
 * is what `docs/online-runtime-boundary.md` asks for when it says provider
 * authorization headers are "always stripped before a destination request or
 * cross-origin redirect". PhishTank's credential is not in a header anyway; it
 * is in the path of the URL this updater builds, and the CDN hop's path is
 * chosen by PhishTank's own `Location`, so the key is not re-sent there either.
 *
 * `baseUrl` is still not the way to reach the CDN, which was worth measuring
 * rather than assuming: the redirect target is `/datadumps/verified_online.csv`
 * under a CloudFront signature bound to that exact path, so a base pointed at
 * it still has `online-valid.csv` appended and answers `404`. Follow the hop —
 * which is now the default — rather than trying to name its target. Verified
 * 2026-09-05 against the live feed with no app key at all: the updater below
 * parsed and stored 74,539 records over a redirect-following client.
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
  // With no key, the same feed is requested without that path segment — the
  // public form, which is what PhishTank actually serves (see the docblock).
  const base = (options.baseUrl ?? PHISHTANK_DATA_BASE_URL).replace(/\/+$/, "");
  const url =
    appKey === undefined
      ? `${base}/${PHISHTANK_ONLINE_VALID_FEED}`
      : `${base}/${appKey.reveal()}/${PHISHTANK_ONLINE_VALID_FEED}`;
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
