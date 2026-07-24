/**
 * Caller-owned threat-feed mirror adapters (Epic M).
 *
 * M4a ships the URLhaus Auth-Key dump updater: authenticate with a caller-owned
 * Auth-Key, download the URLhaus Community API export, parse it into a normalized
 * snapshot, and hand it to a caller-owned store for atomic replacement. The
 * exact-URL lookup and evidence mapping (M4b) build on these primitives.
 *
 * URLhaus datasets are caller-owned: they are never bundled in this package or
 * redistributed.
 */

export {
  URLHAUS_ONLINE_DUMP_URL,
  URLHAUS_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_ID,
  URLHAUS_SOURCE_VERSION,
} from "./urlhaus-descriptor.js";
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
  UrlhausRecord,
  UrlhausSnapshot,
  UrlhausSnapshotMetadata,
  UrlhausSnapshotStore,
  UrlhausUpdateResult,
  UrlhausUrlStatus,
} from "./types.js";
