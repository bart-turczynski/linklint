/**
 * Caller-owned PhishTank mirror types (LINK-lddpffio M5a, LINK-unqxyfce M5b).
 *
 * PhishTank's downloadable *online-valid* feed lists verified, currently-online
 * phishing URLs. M5a authenticates with a caller-owned application key and a
 * descriptive user agent, downloads the feed on an hourly/ETag cadence, and hands
 * a normalized snapshot to caller-owned storage for atomic replacement. M5b does
 * exact-URL local lookup against that snapshot (M5b).
 *
 * A lookup is local, so it discloses nothing at query time. The feed download
 * authenticates to PhishTank but transmits no inspected subject. The dataset is
 * caller-owned and is never bundled or redistributed.
 *
 * NOTE: PhishTank places the application key in the download URL *path*, not a
 * header. The updater substitutes the revealed key only when building the request
 * URL and never stores that keyed URL in metadata, results, evidence, or causes.
 * The key is optional (LINK-plfzjlxg) — PhishTank serves this feed unkeyed — but
 * when one is supplied it still travels in that path segment, so the URL is still
 * treated as a secret.
 */

import type { OnlineSecret } from "../sources/index.js";

/** Minimal provider-scoped HTTP client for the feed download (bypasses L0). */
export interface PhishTankHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  /** Decoded response body text (the feed is CSV). Empty on a 304. */
  readonly body: string;
}

export interface PhishTankHttpRequest {
  /** The fully-resolved download URL, including the app key in its path. */
  readonly url: string;
  /** Request headers, including the descriptive `User-Agent` and conditional refresh headers. */
  readonly headers: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
}

export interface PhishTankHttpClient {
  request(request: PhishTankHttpRequest): Promise<PhishTankHttpResponse>;
}

/** A monotonic-enough observation clock; injected for deterministic fixtures. */
export interface PhishTankClock {
  now(): Date;
}

/**
 * A single normalized PhishTank record: one verified phishing URL. Every absent
 * or unparseable field becomes `null`. Exact-URL matching is M5b.
 */
export interface PhishTankRecord {
  /** PhishTank phish id, as text. */
  readonly phishId: string;
  /** The listed phishing URL, verbatim. */
  readonly url: string;
  /** Human-facing PhishTank detail page, or `null`. */
  readonly detailUrl: string | null;
  /** ISO-8601 submission instant, or `null`. */
  readonly submissionTime: string | null;
  /** Whether PhishTank has human-verified the report. */
  readonly verified: boolean;
  /** ISO-8601 verification instant, or `null`. */
  readonly verificationTime: string | null;
  /** Whether the phish was reported still online at export time. */
  readonly online: boolean;
  /** The impersonated brand/target (e.g. `PayPal`, `Other`), or `null`. */
  readonly target: string | null;
}

/** Freshness and conditional-refresh metadata for a stored PhishTank snapshot. */
export interface PhishTankSnapshotMetadata {
  readonly source: string;
  readonly version: string;
  readonly etag: string | null;
  readonly lastModified: string | null;
  readonly observedAt: string;
  readonly expiresAt: string | null;
  readonly recordCount: number;
}

/** A complete, JSON-safe PhishTank snapshot: metadata plus every normalized record. */
export interface PhishTankSnapshot {
  readonly metadata: PhishTankSnapshotMetadata;
  readonly records: readonly PhishTankRecord[];
}

/** Caller-owned snapshot store. `replace` MUST swap the snapshot atomically. */
export interface PhishTankSnapshotStore {
  readMetadata(): Promise<PhishTankSnapshotMetadata | null>;
  replace(snapshot: PhishTankSnapshot): Promise<void>;
}

/**
 * Read-only exact-URL lookup view over a PhishTank snapshot (M5b), built once by
 * `createPhishTankIndex`. Exact match only, never broadened to the host.
 */
export interface PhishTankIndex {
  readonly metadata: PhishTankSnapshotMetadata;
  lookup(url: string): PhishTankRecord | null;
}

/** Machine-readable PhishTank updater causes. */
export type PhishTankCauseCode =
  | "phishtank-throttled"
  | "phishtank-http-error"
  | "phishtank-malformed"
  | "phishtank-network-error"
  | "phishtank-caller-aborted";

export interface PhishTankCause {
  readonly code: PhishTankCauseCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/** Total outcome of one snapshot update attempt. */
export type PhishTankUpdateResult =
  | { readonly status: "updated"; readonly snapshot: PhishTankSnapshot }
  | {
      readonly status: "unchanged";
      readonly metadata: PhishTankSnapshotMetadata;
      readonly reason: "not-modified" | "within-cadence";
    }
  | { readonly status: "skipped"; readonly cause: PhishTankCause }
  | { readonly status: "failure"; readonly cause: PhishTankCause };

export interface UpdatePhishTankSnapshotOptions {
  readonly client: PhishTankHttpClient;
  readonly store: PhishTankSnapshotStore;
  /**
   * Caller-owned application key, revealed only into the download URL path.
   *
   * OPTIONAL (LINK-plfzjlxg): PhishTank serves the online-valid feed to an
   * unkeyed request, and a fictional key in the key position gets the same
   * answer as none at all, so requiring one here was a precondition the
   * provider does not impose. Omit it and the public feed URL is requested;
   * supply it and it is still sent, because PhishTank's access policy has
   * changed before and a registered caller should keep identifying itself.
   */
  readonly appKey?: OnlineSecret;
  readonly clock: PhishTankClock;
  /**
   * Base of the PhishTank data URL. The feed filename is appended, with the app
   * key between them when one is supplied: `${baseUrl}/${appKey}/online-valid.csv`,
   * or `${baseUrl}/online-valid.csv` without. Defaults to the PhishTank data host.
   *
   * Note this is NOT a way around the `302` that host answers with: the signed
   * CDN target is `verified_online.csv`, so a base pointed at it still gets
   * `online-valid.csv` appended and answers `404`. Following that hop is a
   * caller-supplied {@link PhishTankHttpClient}'s job (LINK-plfzjlxg).
   */
  readonly baseUrl?: string;
  /**
   * Descriptive `User-Agent` PhishTank requires (e.g. `phishtank/yourusername`).
   * A generic agent is rejected by the provider; a caller SHOULD set its own.
   */
  readonly userAgent?: string;
  /**
   * Refresh cadence, in ms. Drives `expiresAt` and a pre-network cadence guard.
   * Defaults to one hour (PhishTank's stated minimum). Non-positive disables both.
   */
  readonly cadenceMs?: number;
  readonly signal?: AbortSignal;
}
