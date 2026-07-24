/**
 * RDAP source descriptor under the M2 online-source contract (LINK-okdrqxoz).
 *
 * RDAP domain queries are unauthenticated and disclose only the registrable
 * domain to the authoritative registry/registrar, so no credential and no
 * consent gate are required. Responses carry no standard cache directive, so the
 * source declares expiry from a caller-configured TTL and goes stale past it.
 * Scoring is `conjunctive-finding`: M1a emits evidence only, and M1b projects a
 * young-domain finding solely under an explicit threshold with corroborating
 * lexical brand evidence.
 */

import type { OnlineSourceDescriptor } from "../sources/index.js";

import { RDAP_SOURCE_ID, RDAP_SOURCE_VERSION } from "./rdap-client.js";

export const RDAP_SOURCE_DESCRIPTOR: OnlineSourceDescriptor = {
  id: RDAP_SOURCE_ID,
  displayName: "RDAP registration age",
  version: RDAP_SOURCE_VERSION,
  layer: "reputation",
  evidenceScope: ["rdap.domain"],
  disclosure: {
    recipient: "rdap.authoritative-registry",
    sends: ["registrable-domain"],
    consentRequired: [],
  },
  credentials: { kind: "none" },
  terms: {
    supportedModes: ["non-commercial", "fair-use", "commercial"],
    attributionRequired: false,
    redistribution: "permitted",
    caching: "response-directed",
  },
  dataOrigin: { kind: "live-provider", recipient: "rdap.authoritative-registry" },
  freshness: { declaresExpiry: true, staleWhenExpired: true },
  scoring: "conjunctive-finding",
  noMatchSemantics: "absence-is-not-safety",
};
