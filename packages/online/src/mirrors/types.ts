/**
 * Caller-owned URLhaus mirror types (LINK-qzybihpz, M4a).
 *
 * M4a owns the *updater* half of the URLhaus source: authenticate with a
 * caller-owned Auth-Key, download the URLhaus Community API export, parse it into
 * a normalized snapshot, and hand that snapshot to caller-owned storage for
 * atomic replacement. The exact-URL lookup and evidence mapping are M4b
 * (LINK-ifpdilfn); nothing here scores a verdict or emits evidence.
 *
 * URLhaus is queried against a *local* snapshot, so a lookup discloses nothing at
 * query time. The dump download authenticates to abuse.ch but transmits no
 * inspected subject — it fetches the whole dataset. The dataset is caller-owned
 * and is never bundled in the npm artifact or redistributed.
 */

import type { OnlineSecret } from "../sources/index.js";

/**
 * Minimal provider-scoped HTTP client for the dump download. URLhaus is a
 * provider service, not an inspected destination, so it does NOT pass through the
 * L0 destination boundary; callers inject a deterministic client in tests and a
 * bounded Node client in production. The client is responsible for transport-level
 * decoding (e.g. gunzip) and yields the decoded CSV text.
 */
export interface UrlhausHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  /** Decoded response body text (URLhaus dumps are CSV). Empty on a 304. */
  readonly body: string;
}

export interface UrlhausHttpRequest {
  readonly url: string;
  /**
   * Request headers, including the `Auth-Key` credential and any conditional
   * refresh headers. The credential value is revealed into this map at the
   * moment of the request and nowhere else.
   */
  readonly headers: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
}

export interface UrlhausHttpClient {
  request(request: UrlhausHttpRequest): Promise<UrlhausHttpResponse>;
}

/** A monotonic-enough observation clock; injected for deterministic fixtures. */
export interface UrlhausClock {
  now(): Date;
}

/** URLhaus reported liveness of a listed URL at export time. */
export type UrlhausUrlStatus = "online" | "offline" | "unknown";

/**
 * A single normalized URLhaus record: one known malware-distribution URL. Every
 * absent or unparseable field becomes `null` (or an empty list) — never a
 * fabricated default. Exact-URL matching against these records is M4b.
 */
export interface UrlhausRecord {
  /** URLhaus record id, as text. */
  readonly id: string;
  /** The listed malware-distribution URL, verbatim. */
  readonly url: string;
  /** ISO-8601 instant the URL was added, or `null` when absent/unparseable. */
  readonly dateAdded: string | null;
  readonly status: UrlhausUrlStatus;
  /** ISO-8601 instant the URL was last seen online, or `null`. */
  readonly lastOnline: string | null;
  /** Threat classification token (e.g. `malware_download`), or `null`. */
  readonly threat: string | null;
  readonly tags: readonly string[];
  readonly reporter: string | null;
}

/**
 * Freshness and conditional-refresh metadata for a stored snapshot. `etag` and
 * `lastModified` are echoed back to the provider on the next update to make a
 * conditional (304-capable) request; `observedAt`/`expiresAt` drive the
 * source-declared freshness. Holds no credential.
 */
export interface UrlhausSnapshotMetadata {
  /** Stable source identity of the mirrored feed. */
  readonly source: string;
  /** Adapter/snapshot format version. */
  readonly version: string;
  /** Provider `ETag`, echoed as `If-None-Match` on refresh, or `null`. */
  readonly etag: string | null;
  /** Provider `Last-Modified`, echoed as `If-Modified-Since` on refresh, or `null`. */
  readonly lastModified: string | null;
  /** ISO-8601 instant this snapshot was downloaded. */
  readonly observedAt: string;
  /** ISO-8601 cadence expiry derived from the configured refresh interval, or `null`. */
  readonly expiresAt: string | null;
  /** Number of records in the snapshot. */
  readonly recordCount: number;
}

/** A complete, JSON-safe URLhaus snapshot: metadata plus every normalized record. */
export interface UrlhausSnapshot {
  readonly metadata: UrlhausSnapshotMetadata;
  readonly records: readonly UrlhausRecord[];
}

/**
 * Caller-owned snapshot store. The caller supplies the concrete storage
 * (directory, database, object store). `replace` MUST swap the snapshot
 * atomically — a reader never observes a partial dataset — and the updater only
 * ever calls it with a fully-parsed snapshot, so a failed download leaves the
 * previous snapshot intact.
 */
export interface UrlhausSnapshotStore {
  /** Current snapshot metadata for conditional refresh, or `null` when none is stored. */
  readMetadata(): Promise<UrlhausSnapshotMetadata | null>;
  /** Atomically replace the stored snapshot with `snapshot`. */
  replace(snapshot: UrlhausSnapshot): Promise<void>;
}

/** Machine-readable URLhaus updater causes. Distinct from framework degradation codes. */
export type UrlhausCauseCode =
  | "urlhaus-throttled"
  | "urlhaus-http-error"
  | "urlhaus-malformed"
  | "urlhaus-network-error"
  | "urlhaus-caller-aborted";

export interface UrlhausCause {
  readonly code: UrlhausCauseCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/**
 * Total outcome of one snapshot update attempt.
 *
 * - `updated`: a new snapshot was parsed and atomically written.
 * - `unchanged`: the provider reported no change (HTTP 304) or the stored
 *   snapshot is still within the refresh cadence; the store is untouched.
 * - `skipped`: throttling or cancellation prevented completion (retry later).
 * - `failure`: an HTTP error, network error, or malformed dump; the store is
 *   left untouched.
 */
export type UrlhausUpdateResult =
  | { readonly status: "updated"; readonly snapshot: UrlhausSnapshot }
  | {
      readonly status: "unchanged";
      readonly metadata: UrlhausSnapshotMetadata;
      /** Why no download happened: the provider had no change, or cadence guard. */
      readonly reason: "not-modified" | "within-cadence";
    }
  | { readonly status: "skipped"; readonly cause: UrlhausCause }
  | { readonly status: "failure"; readonly cause: UrlhausCause };

export interface UpdateUrlhausSnapshotOptions {
  readonly client: UrlhausHttpClient;
  readonly store: UrlhausSnapshotStore;
  /** Caller-owned Auth-Key. Revealed only into the `Auth-Key` request header. */
  readonly credential: OnlineSecret;
  readonly clock: UrlhausClock;
  /** Dump endpoint. Defaults to the URLhaus online-URLs CSV export. */
  readonly dumpUrl?: string;
  /**
   * Provider refresh cadence, in ms. Drives the snapshot's `expiresAt` and a
   * pre-network cadence guard: a stored snapshot observed more recently than this
   * short-circuits to `unchanged` without contacting the provider (fair use).
   * Non-positive or absent disables both the guard and expiry.
   */
  readonly cadenceMs?: number;
  readonly signal?: AbortSignal;
}
