/**
 * Live TLS certificate source descriptor under the M2 online-source contract
 * (LINK-lmvldqop, M7b).
 *
 * The source connects to the inspected HTTPS origin itself — through the L0 safe
 * pinned transport's observational TLS capability (M7a) — so the recipient is that
 * origin, and the only disclosure is the `host` a TLS connection makes
 * server-visible (SNI plus the connection). No credential and no separate consent
 * gate are required: the connection IS the inspection. The observation is a live,
 * point-in-time snapshot, so it declares no expiry and freshness stays `unknown`.
 *
 * Scoring is `evidence-only`: certificate state (DV posture, validity window,
 * SANs, trust, hostname match) is neutral on its own — DV alone is not risk — so
 * this slice emits attributed evidence and NEVER a scored finding. A conjunctive
 * TLS finding that combines certificate state with stronger phishing indicators
 * can be added later without changing this descriptor's honesty pin.
 */

import type { OnlineSourceDescriptor } from "../sources/index.js";

export const TLS_SOURCE_ID = "tls.live-endpoint" as const;
export const TLS_SOURCE_VERSION = "1.0.0" as const;

/** Stable evidence type this source emits. */
export const TLS_CERTIFICATE_EVIDENCE_TYPE = "tls.certificate" as const;

export const TLS_SOURCE_DESCRIPTOR: OnlineSourceDescriptor = {
  id: TLS_SOURCE_ID,
  displayName: "Live TLS certificate",
  version: TLS_SOURCE_VERSION,
  layer: "reputation",
  evidenceScope: [TLS_CERTIFICATE_EVIDENCE_TYPE],
  disclosure: {
    recipient: "tls.inspected-origin",
    sends: ["host"],
    consentRequired: [],
  },
  credentials: { kind: "none" },
  terms: {
    supportedModes: ["non-commercial", "fair-use", "commercial"],
    attributionRequired: false,
    redistribution: "permitted",
    caching: "response-directed",
  },
  dataOrigin: { kind: "live-provider", recipient: "tls.inspected-origin" },
  freshness: { declaresExpiry: false, staleWhenExpired: false },
  scoring: "evidence-only",
  noMatchSemantics: "absence-is-not-safety",
};
