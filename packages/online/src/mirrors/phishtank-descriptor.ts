/**
 * PhishTank source descriptor under the M2 online-source contract (LINK-lddpffio).
 *
 * PhishTank is a caller-owned local mirror: the online-valid feed is downloaded
 * with a caller-owned application key and queried locally, so a lookup discloses
 * nothing at query time (`sends: ["none"]`) and the dataset is never bundled or
 * redistributed (`caller-owned-mirror`, `bundled: false`, redistribution
 * `caller-owned-only`). PhishTank grants free use with attribution; commercial
 * use is not assumed, so `commercial` is NOT a supported mode. The snapshot
 * carries a cadence-derived expiry (hourly by default) and goes stale past it.
 *
 * Scoring is `conjunctive-finding`: an exact, within-freshness match to a
 * verified, online record is affirmative subject-tied evidence M5b projects a
 * finding from. A miss, an unverified/offline record, or a stale snapshot stays
 * evidence-only — absence is never safety.
 */

import type { OnlineSourceDescriptor } from "../sources/index.js";

export const PHISHTANK_SOURCE_ID = "phishtank.mirror" as const;
export const PHISHTANK_SOURCE_VERSION = "1.0.0" as const;

/** Default PhishTank data host. The app key and feed filename are appended per call. */
export const PHISHTANK_DATA_BASE_URL = "https://data.phishtank.com/data" as const;

/** PhishTank feed filename for the verified, currently-online phishing URLs. */
export const PHISHTANK_ONLINE_VALID_FEED = "online-valid.csv" as const;

/** Default hourly refresh cadence, in ms — PhishTank's stated minimum interval. */
export const PHISHTANK_DEFAULT_CADENCE_MS = 3_600_000;

export const PHISHTANK_SOURCE_DESCRIPTOR: OnlineSourceDescriptor = {
  id: PHISHTANK_SOURCE_ID,
  displayName: "PhishTank caller-owned mirror",
  version: PHISHTANK_SOURCE_VERSION,
  layer: "reputation",
  evidenceScope: ["phishtank.match"],
  disclosure: {
    recipient: "local-mirror",
    sends: ["none"],
    consentRequired: [],
  },
  credentials: { kind: "required", scheme: "app-key", label: "PhishTank application key" },
  terms: {
    supportedModes: ["non-commercial", "fair-use"],
    attributionRequired: true,
    redistribution: "caller-owned-only",
    caching: "permitted",
  },
  dataOrigin: { kind: "caller-owned-mirror", bundled: false },
  freshness: { declaresExpiry: true, staleWhenExpired: true },
  scoring: "conjunctive-finding",
  noMatchSemantics: "absence-is-not-safety",
};
