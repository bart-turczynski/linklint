/**
 * DNS state source descriptor under the M2 online-source contract (LINK-diataibn,
 * M9a1).
 *
 * The source queries a recursive resolver for the inspected host's A/AAAA and the
 * registrable domain's NS/MX, so the recipient is that resolver and the only
 * disclosure is the queried names (the host and its registrable domain). No
 * credential and no consent gate are required — an ordinary DNS lookup carries no
 * secret. The observation is a live, point-in-time snapshot; like the live TLS
 * source it declares no expiry and freshness stays `unknown`, even though record
 * TTLs are preserved as evidence data.
 *
 * Scoring is `evidence-only`: DNS state — which addresses resolve, how mail is
 * routed, which nameservers are delegated — is neutral on its own. A domain with
 * a null MX or an NXDOMAIN answer is neither safe nor malicious by that fact, so
 * this source emits attributed `dns.records` evidence and NEVER a scored finding.
 *
 * The same source also reports the zone's DNSSEC validation state as attributed
 * `dns.dnssec` evidence (M9a2). This too is neutral: an unsigned/`insecure` zone
 * is not risk, and even a `bogus` (validation-failed) zone is only an anomaly —
 * often a misconfiguration — so it stays evidence-only and NEVER a scored finding.
 */

import type { OnlineSourceDescriptor } from "../sources/index.js";

export const DNS_SOURCE_ID = "dns.state" as const;
export const DNS_SOURCE_VERSION = "1.0.0" as const;

/** Stable evidence type this source emits. */
export const DNS_RECORDS_EVIDENCE_TYPE = "dns.records" as const;

/**
 * Stable evidence type for the DNSSEC validation state (M9a2). Evidence-only and
 * neutral: `insecure`/absence is never risk and only `bogus` is an anomaly, yet
 * even bogus is emitted as attributed evidence, never a scored finding.
 */
export const DNS_DNSSEC_EVIDENCE_TYPE = "dns.dnssec" as const;

export const DNS_SOURCE_DESCRIPTOR: OnlineSourceDescriptor = {
  id: DNS_SOURCE_ID,
  displayName: "DNS record state",
  version: DNS_SOURCE_VERSION,
  layer: "reputation",
  evidenceScope: [DNS_RECORDS_EVIDENCE_TYPE, DNS_DNSSEC_EVIDENCE_TYPE],
  disclosure: {
    recipient: "dns.resolver",
    sends: ["registrable-domain", "host"],
    consentRequired: [],
  },
  credentials: { kind: "none" },
  terms: {
    supportedModes: ["non-commercial", "fair-use", "commercial"],
    attributionRequired: false,
    redistribution: "permitted",
    caching: "response-directed",
  },
  dataOrigin: { kind: "live-provider", recipient: "dns.resolver" },
  freshness: { declaresExpiry: false, staleWhenExpired: false },
  scoring: "evidence-only",
  noMatchSemantics: "absence-is-not-safety",
};
