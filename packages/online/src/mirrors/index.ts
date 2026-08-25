/**
 * Caller-owned threat-feed mirror adapters (Epic M).
 *
 * M4a ships the URLhaus Auth-Key dump updater: authenticate with a caller-owned
 * Auth-Key, download the URLhaus Community API export, parse it into a normalized
 * snapshot, and hand it to a caller-owned store for atomic replacement. M4b adds
 * the exact-URL local lookup index and the `malware_url_listed` reputation
 * enricher on top of those primitives.
 *
 * URLhaus datasets are caller-owned: they are never bundled in this package or
 * redistributed.
 *
 * LINK-mpkglaqb adds the two concrete Node HTTP clients that make both updaters
 * runnable. It deliberately does NOT add a snapshot store: the caller supplies
 * the directory, database or object store, exactly as
 * `docs/online-runtime-boundary.md` requires and as the RDAP bootstrap updater
 * already does. `packages/online/README.md` carries a worked fs-backed example.
 */

export {
  URLHAUS_ONLINE_DUMP_URL,
  URLHAUS_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_ID,
  URLHAUS_SOURCE_VERSION,
} from "./urlhaus-descriptor.js";
export { canonicalizeUrl, createUrlhausIndex } from "./urlhaus-index.js";
export { createUrlhausEnricher } from "./urlhaus-enricher.js";
export type { UrlhausEnricherOptions } from "./urlhaus-enricher.js";
export {
  createNodeUrlhausHttpClient,
  UrlhausHttpAbortError,
  UrlhausHttpFailure,
} from "./urlhaus-node.js";
export type { NodeUrlhausHttpClientOptions } from "./urlhaus-node.js";
export { parseUrlhausCsv } from "./urlhaus-parse.js";
export { updateUrlhausSnapshot } from "./urlhaus-updater.js";
export type {
  UpdateUrlhausSnapshotOptions,
  UrlhausCause,
  UrlhausCauseCode,
  UrlhausClock,
  UrlhausHttpClient,
  UrlhausHttpRequest,
  UrlhausHttpResponse,
  UrlhausIndex,
  UrlhausRecord,
  UrlhausSnapshot,
  UrlhausSnapshotMetadata,
  UrlhausSnapshotStore,
  UrlhausUpdateResult,
  UrlhausUrlStatus,
} from "./types.js";

export {
  PHISHTANK_DATA_BASE_URL,
  PHISHTANK_DEFAULT_CADENCE_MS,
  PHISHTANK_ONLINE_VALID_FEED,
  PHISHTANK_SOURCE_DESCRIPTOR,
  PHISHTANK_SOURCE_ID,
  PHISHTANK_SOURCE_VERSION,
} from "./phishtank-descriptor.js";
export { createPhishTankIndex } from "./phishtank-index.js";
export { createPhishTankEnricher } from "./phishtank-enricher.js";
export type { PhishTankEnricherOptions } from "./phishtank-enricher.js";
export {
  createNodePhishTankHttpClient,
  PhishTankHttpAbortError,
  PhishTankHttpFailure,
} from "./phishtank-node.js";
export type { NodePhishTankHttpClientOptions } from "./phishtank-node.js";
export { parsePhishTankCsv } from "./phishtank-parse.js";
export { updatePhishTankSnapshot } from "./phishtank-updater.js";
export type {
  PhishTankCause,
  PhishTankCauseCode,
  PhishTankClock,
  PhishTankHttpClient,
  PhishTankHttpRequest,
  PhishTankHttpResponse,
  PhishTankIndex,
  PhishTankRecord,
  PhishTankSnapshot,
  PhishTankSnapshotMetadata,
  PhishTankSnapshotStore,
  PhishTankUpdateResult,
  UpdatePhishTankSnapshotOptions,
} from "./phishtank-types.js";
