/**
 * URLhaus source descriptor under the M2 online-source contract (LINK-qzybihpz).
 *
 * URLhaus is a caller-owned local mirror: the dataset is downloaded once with a
 * caller-owned Auth-Key and queried locally, so a lookup discloses nothing at
 * query time (`sends: ["none"]`) and the dataset is never bundled or
 * redistributed (`caller-owned-mirror`, `bundled: false`, redistribution
 * `caller-owned-only`). abuse.ch grants free non-commercial / fair use with
 * attribution; commercial use needs a separate plan, so `commercial` is NOT a
 * supported mode and requesting it is a construction error rather than a silent
 * downgrade. The snapshot carries a cadence-derived expiry and goes stale past it.
 *
 * Scoring is `conjunctive-finding`: an exact, within-freshness URLhaus match is
 * affirmative subject-tied evidence M4b (LINK-ifpdilfn) may project a finding
 * from. A miss or a stale snapshot stays evidence-only — absence is never safety.
 */

import type { OnlineSourceDescriptor } from "../sources/index.js";

export const URLHAUS_SOURCE_ID = "urlhaus.mirror" as const;
export const URLHAUS_SOURCE_VERSION = "1.0.0" as const;

/** Default URLhaus online-URLs CSV export endpoint. Overridable per updater call. */
export const URLHAUS_ONLINE_DUMP_URL = "https://urlhaus.abuse.ch/downloads/csv_online/" as const;

export const URLHAUS_SOURCE_DESCRIPTOR: OnlineSourceDescriptor = {
  id: URLHAUS_SOURCE_ID,
  displayName: "URLhaus caller-owned mirror",
  version: URLHAUS_SOURCE_VERSION,
  layer: "reputation",
  evidenceScope: ["urlhaus.match"],
  disclosure: {
    recipient: "local-mirror",
    sends: ["none"],
    consentRequired: [],
  },
  credentials: { kind: "required", scheme: "auth-key", label: "URLhaus Auth-Key" },
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
