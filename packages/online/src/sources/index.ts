/**
 * Blocking online-source contract (LINK-nlnyqofz, M2).
 *
 * The shared provenance / privacy / licensing / BYOK surface every Epic M
 * provider adapter declares and satisfies before it may reach the network or
 * disclose an inspected subject. See docs/online-source-contract.md.
 */

export { createOnlineSecret, isOnlineSecret, REDACTED_SECRET } from "./secret.js";
export type { OnlineSecret } from "./secret.js";

export {
  assertValidSourceDescriptor,
  freshnessFor,
  OnlineSourceConfigError,
  preflightOnlineSource,
} from "./contract.js";
export type {
  DisclosureConsent,
  OnlineSourceConfig,
  OnlineSourceConfigErrorCode,
  OnlineSourcePreflight,
  OnlineSourceSkipCode,
} from "./contract.js";

export type {
  CachingMode,
  CommercialMode,
  ConsentGatedChannel,
  CredentialRequirement,
  CredentialScheme,
  DataOrigin,
  DisclosureChannel,
  DisclosureProfile,
  FreshnessCapability,
  OnlineSourceDescriptor,
  OnlineSourceLayer,
  RedistributionMode,
  ScoringPolicy,
  TermsProfile,
} from "./types.js";
