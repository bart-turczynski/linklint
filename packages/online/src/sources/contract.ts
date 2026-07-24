/**
 * Runtime enforcement of the online-source contract (LINK-nlnyqofz, M2).
 *
 * Two enforcement seams, matching the two failure kinds the boundary distinguishes:
 *
 * 1. TERMS are a construction gate. Requesting a commercial mode a source does
 *    not support, or declining required attribution, throws {@link
 *    OnlineSourceConfigError}. A source is never constructed under terms it
 *    cannot honor and never silently downgraded.
 * 2. CREDENTIALS and DISCLOSURE are runtime gates. A missing required credential
 *    or an un-granted consent-gated channel yields a structured skip cause, so
 *    the operation degrades to `skipped`/`checksSkipped` with a machine-readable
 *    reason — never a fabricated safety claim and never an anonymous fallback.
 *
 * Descriptor validation (`assertValidSourceDescriptor`) rejects malformed
 * contracts up front so downstream gates and evidence builders can trust shape.
 */

import type { EnrichmentCause, EnrichmentFreshness } from "linklint";

import { isOnlineSecret, type OnlineSecret } from "./secret.js";
import type {
  CommercialMode,
  ConsentGatedChannel,
  DisclosureChannel,
  FreshnessCapability,
  OnlineSourceDescriptor,
} from "./types.js";

const DISCLOSURE_CHANNELS: readonly DisclosureChannel[] = [
  "none",
  "registrable-domain",
  "host",
  "url-prefix-hash",
  "full-url",
  "client-ip",
  "watchlist",
];

const CONSENT_GATED_CHANNELS: readonly ConsentGatedChannel[] = [
  "full-url",
  "client-ip",
  "watchlist",
];

const COMMERCIAL_MODES: readonly CommercialMode[] = [
  "non-commercial",
  "fair-use",
  "commercial",
];

/** Machine-readable reasons a source cannot be constructed under a caller's terms. */
export type OnlineSourceConfigErrorCode =
  | "invalid-descriptor"
  | "unsupported-commercial-mode"
  | "attribution-not-accepted";

/**
 * A construction-time terms/licensing violation. Thrown, not returned, because a
 * source under unacceptable terms must never come into existence.
 */
export class OnlineSourceConfigError extends Error {
  readonly code: OnlineSourceConfigErrorCode;
  readonly sourceId: string;

  constructor(code: OnlineSourceConfigErrorCode, sourceId: string, message: string) {
    super(message);
    this.name = "OnlineSourceConfigError";
    this.code = code;
    this.sourceId = sourceId;
  }
}

/** Machine-readable runtime skip reasons shared by every online source. */
export type OnlineSourceSkipCode =
  | "credentials-missing"
  | "disclosure-consent-required";

/** Caller configuration resolved against a descriptor before any operation runs. */
export interface OnlineSourceConfig {
  /** The commercial posture the caller operates under. Must be a supported mode. */
  readonly commercialMode: CommercialMode;
  /** Required when `terms.attributionRequired`; acknowledges the attribution duty. */
  readonly acceptAttribution?: boolean;
  /** Caller-owned BYOK secret. Required for a `required` credential source. */
  readonly credential?: OnlineSecret;
  /** Per-operation consent for otherwise-refused disclosure channels. */
  readonly consent?: DisclosureConsent;
}

/** The consent-gated disclosure channels the caller has explicitly authorized. */
export interface DisclosureConsent {
  readonly allow: readonly ConsentGatedChannel[];
}

/**
 * The result of resolving a caller config against a descriptor. `ok: false`
 * carries a ready-to-emit skip cause; construction-time terms failures throw
 * instead of surfacing here.
 */
export type OnlineSourcePreflight =
  | {
      readonly ok: true;
      /** Revealed only at the provider authorization boundary; never logged. */
      readonly credential: OnlineSecret | null;
      /** The disclosure channels cleared for this operation. */
      readonly disclosure: readonly DisclosureChannel[];
    }
  | { readonly ok: false; readonly cause: EnrichmentCause };

/**
 * Validate a descriptor's shape and internal consistency. Throws {@link
 * OnlineSourceConfigError} with `invalid-descriptor` on any violation so a
 * malformed contract cannot reach the runtime gates.
 */
export function assertValidSourceDescriptor(
  descriptor: OnlineSourceDescriptor,
): void {
  const id = typeof descriptor?.id === "string" ? descriptor.id : "<unknown>";
  const fail = (message: string): never => {
    throw new OnlineSourceConfigError("invalid-descriptor", id, message);
  };

  if (!isNonEmptyString(descriptor?.id)) fail("descriptor.id must be a non-empty string");
  if (!isNonEmptyString(descriptor.displayName)) fail("descriptor.displayName is required");
  if (!isNonEmptyString(descriptor.version)) fail("descriptor.version is required");
  if (descriptor.layer !== "resolution" && descriptor.layer !== "reputation") {
    fail("descriptor.layer must be 'resolution' or 'reputation'");
  }
  if (
    !Array.isArray(descriptor.evidenceScope) ||
    descriptor.evidenceScope.length === 0 ||
    !descriptor.evidenceScope.every(isNonEmptyString)
  ) {
    fail("descriptor.evidenceScope must be a non-empty list of evidence type tokens");
  }

  const disclosure = descriptor.disclosure;
  if (!isNonEmptyString(disclosure?.recipient)) fail("disclosure.recipient is required");
  if (
    !Array.isArray(disclosure.sends) ||
    disclosure.sends.length === 0 ||
    !disclosure.sends.every((channel) => DISCLOSURE_CHANNELS.includes(channel))
  ) {
    fail("disclosure.sends must be a non-empty list of known channels");
  }
  if (disclosure.sends.includes("none") && disclosure.sends.length !== 1) {
    fail("disclosure.sends of 'none' must be the sole channel");
  }
  if (!Array.isArray(disclosure.consentRequired)) {
    fail("disclosure.consentRequired must be an array");
  }
  for (const channel of disclosure.consentRequired) {
    if (!CONSENT_GATED_CHANNELS.includes(channel)) {
      fail(`disclosure.consentRequired lists non-gated channel '${String(channel)}'`);
    }
    if (!disclosure.sends.includes(channel)) {
      fail(`disclosure.consentRequired '${channel}' is not among disclosure.sends`);
    }
  }
  // Every consent-gated channel that IS sent must be declared consent-required;
  // a source cannot quietly send a full URL without gating it.
  for (const channel of disclosure.sends) {
    if (
      CONSENT_GATED_CHANNELS.includes(channel as ConsentGatedChannel) &&
      !disclosure.consentRequired.includes(channel as ConsentGatedChannel)
    ) {
      fail(`disclosure.sends '${channel}' must be listed in consentRequired`);
    }
  }

  const credentials = descriptor.credentials;
  if (credentials?.kind === "required" || credentials?.kind === "optional") {
    if (!isNonEmptyString(credentials.label)) fail("credentials.label is required");
  } else if (credentials?.kind !== "none") {
    fail("credentials.kind must be 'none', 'required', or 'optional'");
  }

  const terms = descriptor.terms;
  if (
    !Array.isArray(terms?.supportedModes) ||
    terms.supportedModes.length === 0 ||
    !terms.supportedModes.every((mode) => COMMERCIAL_MODES.includes(mode))
  ) {
    fail("terms.supportedModes must be a non-empty list of commercial modes");
  }
  if (typeof terms.attributionRequired !== "boolean") {
    fail("terms.attributionRequired must be a boolean");
  }

  const origin = descriptor.dataOrigin;
  if (origin?.kind === "live-provider") {
    if (!isNonEmptyString(origin.recipient)) fail("dataOrigin.recipient is required");
  } else if (origin?.kind === "caller-owned-mirror") {
    if (origin.bundled !== false) fail("dataOrigin.bundled must be false for a mirror");
  } else {
    fail("dataOrigin.kind must be 'live-provider' or 'caller-owned-mirror'");
  }

  if (
    typeof descriptor.freshness?.declaresExpiry !== "boolean" ||
    typeof descriptor.freshness?.staleWhenExpired !== "boolean"
  ) {
    fail("freshness.declaresExpiry and freshness.staleWhenExpired must be booleans");
  }
  if (descriptor.scoring !== "evidence-only" && descriptor.scoring !== "conjunctive-finding") {
    fail("descriptor.scoring must be 'evidence-only' or 'conjunctive-finding'");
  }
  if (descriptor.noMatchSemantics !== "absence-is-not-safety") {
    fail("descriptor.noMatchSemantics must be the literal 'absence-is-not-safety'");
  }
}

/**
 * Resolve caller configuration against a descriptor. Enforces the TERMS gate
 * (throws on unsupported mode or declined attribution) and then the runtime
 * credential/disclosure gates (returns a skip cause). A successful preflight
 * hands back the credential to reveal at the provider boundary and the cleared
 * disclosure channels.
 */
export function preflightOnlineSource(
  descriptor: OnlineSourceDescriptor,
  config: OnlineSourceConfig,
): OnlineSourcePreflight {
  assertValidSourceDescriptor(descriptor);

  // --- Terms gate (construction-time; throws) ---
  if (!descriptor.terms.supportedModes.includes(config.commercialMode)) {
    throw new OnlineSourceConfigError(
      "unsupported-commercial-mode",
      descriptor.id,
      `Source '${descriptor.id}' does not support commercial mode '${config.commercialMode}'; ` +
        `supported: ${descriptor.terms.supportedModes.join(", ")}`,
    );
  }
  if (descriptor.terms.attributionRequired && config.acceptAttribution !== true) {
    throw new OnlineSourceConfigError(
      "attribution-not-accepted",
      descriptor.id,
      `Source '${descriptor.id}' requires attribution; set config.acceptAttribution = true`,
    );
  }

  // --- Credential gate (runtime; skip cause) ---
  if (descriptor.credentials.kind === "required") {
    if (!isOnlineSecret(config.credential)) {
      return {
        ok: false,
        cause: {
          code: "credentials-missing",
          message: `Source '${descriptor.id}' requires the ${descriptor.credentials.label} credential`,
          retryable: false,
          details: { slot: descriptor.credentials.label, scheme: descriptor.credentials.scheme },
        },
      };
    }
  }

  // --- Disclosure gate (runtime; skip cause) ---
  const granted = new Set(config.consent?.allow ?? []);
  const missingConsent = descriptor.disclosure.consentRequired.filter(
    (channel) => !granted.has(channel),
  );
  if (missingConsent.length > 0) {
    return {
      ok: false,
      cause: {
        code: "disclosure-consent-required",
        message:
          `Source '${descriptor.id}' would disclose ${missingConsent.join(", ")} to ` +
          `${descriptor.disclosure.recipient}; grant explicit consent to proceed`,
        retryable: false,
        details: { channels: [...missingConsent], recipient: descriptor.disclosure.recipient },
      },
    };
  }

  const credential = isOnlineSecret(config.credential) ? config.credential : null;
  return { ok: true, credential, disclosure: descriptor.disclosure.sends };
}

/**
 * Build an {@link EnrichmentFreshness} record consistent with the source's
 * declared capability. A source that cannot declare expiry always reports
 * `unknown`; one that can reports `fresh` before expiry and `stale` after,
 * honoring `staleWhenExpired`.
 */
export function freshnessFor(
  capability: FreshnessCapability,
  observedAt: Date,
  expiresAt: Date | null,
): EnrichmentFreshness {
  if (!capability.declaresExpiry || expiresAt === null) {
    return { status: "unknown", expiresAt: null };
  }
  const expired = observedAt.getTime() >= expiresAt.getTime();
  const status = expired && capability.staleWhenExpired ? "stale" : "fresh";
  return { status, expiresAt: expiresAt.toISOString() };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}
