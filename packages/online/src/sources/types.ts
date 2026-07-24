/**
 * Blocking online-source contract types (LINK-nlnyqofz, M2).
 *
 * This is the machine-readable metadata every Epic M provider adapter (RDAP,
 * caller-owned URLhaus/PhishTank mirrors, live TLS, DNS/DNSSEC) MUST publish
 * before it may connect to a network or disclose an inspected subject. It turns
 * the prose policy in docs/online-runtime-boundary.md ("Licensing, privacy, and
 * commercial modes" and "Configuration, credentials, and storage") into a typed,
 * validated, contract-tested surface.
 *
 * Nothing here performs I/O. A descriptor is inert data; the runtime gates in
 * `contract.ts` decide, from a descriptor plus caller configuration, whether an
 * operation may proceed, must be skipped with a structured cause, or is a
 * construction-time terms violation.
 */

import type { EnrichmentLayer } from "linklint";

/** The network-backed layers an online source can attribute evidence to. */
export type OnlineSourceLayer = EnrichmentLayer;

/**
 * A channel of subject data that could leave the machine. Ordered from least to
 * most disclosing. `none` is a purely local computation (for example a
 * caller-owned mirror lookup that never contacts the provider at query time).
 */
export type DisclosureChannel =
  | "none"
  | "registrable-domain"
  | "host"
  | "url-prefix-hash"
  | "full-url"
  | "client-ip"
  | "watchlist";

/**
 * The disclosure channels that MUST be individually consented to per operation.
 * Destination-fetch authorization never implies provider-disclosure consent, so
 * these are gated separately and default to refused.
 */
export type ConsentGatedChannel = Extract<
  DisclosureChannel,
  "full-url" | "client-ip" | "watchlist"
>;

/** Exactly what a source discloses, to whom, and which channels are consent-gated. */
export interface DisclosureProfile {
  /** Stable recipient identity, e.g. `rdap.arin`, `urlhaus.abuse.ch`, or `local-mirror`. */
  readonly recipient: string;
  /** Every channel this source can transmit. `none` MUST be the sole entry when nothing leaves. */
  readonly sends: readonly DisclosureChannel[];
  /** Subset of `sends` that requires explicit per-operation consent before transmission. */
  readonly consentRequired: readonly ConsentGatedChannel[];
}

/** Licence/commercial posture a caller can select for a source. */
export type CommercialMode = "non-commercial" | "fair-use" | "commercial";

/** Whether provider data may be re-shared, and under what ownership. */
export type RedistributionMode = "prohibited" | "caller-owned-only" | "permitted";

/** Whether source responses may be persisted, and under whose direction. */
export type CachingMode = "prohibited" | "response-directed" | "permitted";

/**
 * Executable licensing gate. `supportedModes` is the closed set of commercial
 * postures the source's terms allow; requesting any other mode is a construction
 * error, never a silent downgrade.
 */
export interface TermsProfile {
  readonly supportedModes: readonly CommercialMode[];
  /** When true, the caller must acknowledge attribution to construct the source. */
  readonly attributionRequired: boolean;
  readonly redistribution: RedistributionMode;
  readonly caching: CachingMode;
}

/** The credential scheme a provider authenticates with. */
export type CredentialScheme = "auth-key" | "app-key" | "bearer" | "basic";

/**
 * Whether a caller-owned secret is needed. A `required` credential that is absent
 * is an explicit skip, never an interactive prompt or a fallback to an anonymous
 * service.
 */
export type CredentialRequirement =
  | { readonly kind: "none" }
  | {
      readonly kind: "required" | "optional";
      readonly scheme: CredentialScheme;
      /** Human-readable slot name, e.g. `URLhaus Auth-Key`. Never the value. */
      readonly label: string;
    };

/**
 * Where the evidence originates. A caller-owned mirror is queried locally and its
 * dataset is never bundled in the npm artifact or silently redistributed;
 * `bundled` is pinned `false` to make that a type-level guarantee.
 */
export type DataOrigin =
  | { readonly kind: "live-provider"; readonly recipient: string }
  | { readonly kind: "caller-owned-mirror"; readonly bundled: false };

/**
 * How a source relates to the deterministic lexical score.
 *
 * `evidence-only` sources are additive and NEVER contribute scored findings:
 * they extend the result with attributed, informational evidence (the L3/L4/L5
 * precedent). `conjunctive-finding` sources MAY contribute findings, but only
 * from affirmative, subject-tied, within-freshness evidence — they still never
 * replace the lexical verdict, and a no-match or degraded observation stays
 * evidence-only.
 */
export type ScoringPolicy = "evidence-only" | "conjunctive-finding";

/** What freshness a source can honestly assert about its observations. */
export interface FreshnessCapability {
  /** True when the source can emit a concrete `expiresAt`; false keeps freshness `unknown`. */
  readonly declaresExpiry: boolean;
  /** True when an observation past its expiry MUST be reported `stale` rather than dropped. */
  readonly staleWhenExpired: boolean;
}

/**
 * The complete, inert contract descriptor an online source publishes. Validated
 * by `assertValidSourceDescriptor`; consumed by the runtime gates and the shared
 * contract-test kit.
 */
export interface OnlineSourceDescriptor {
  /** Stable source identity; matches the producing enricher's `id`. */
  readonly id: string;
  /** Human-facing name for attribution and diagnostics. */
  readonly displayName: string;
  /** Adapter/contract version string. */
  readonly version: string;
  readonly layer: OnlineSourceLayer;
  /** Stable evidence `type` tokens this source is permitted to emit. */
  readonly evidenceScope: readonly string[];
  readonly disclosure: DisclosureProfile;
  readonly credentials: CredentialRequirement;
  readonly terms: TermsProfile;
  readonly dataOrigin: DataOrigin;
  readonly freshness: FreshnessCapability;
  readonly scoring: ScoringPolicy;
  /**
   * Literal honesty pin. Every online source agrees that a completed query with
   * no match is evidence about one source at one time, never a safety claim.
   */
  readonly noMatchSemantics: "absence-is-not-safety";
}
