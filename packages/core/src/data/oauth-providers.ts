/**
 * Legitimate OAuth / identity-provider allowlist — a SMALL, conservative set of
 * registrable domains (eTLD+1) that legitimately serve OAuth / token-flow
 * endpoints. It exists solely for the agent-gated `credential_harvesting`
 * detector (V4c): it gates that detector OFF on the providers where OAuth /
 * token markers (`/oauth/authorize`, `redirect_uri=`, `access_token=`, …) are
 * PERFECTLY LEGITIMATE, so the detector only fires when the same shape appears
 * on an UNKNOWN host.
 *
 * Why an allowlist (not a watchlist):
 *   - The OAuth/token markers themselves are benign signals — they describe a
 *     real, common protocol. They become suspicious only on a host that is NOT a
 *     recognized identity provider. So the data we pin is the set of hosts that
 *     MUST NOT fire, tested as an exact eTLD+1 membership check.
 *   - This is the inverse of the api-brands tier (a watchlist of impersonated
 *     tokens); here we suppress on known-good registrable domains.
 *
 * Kept SMALL and high-confidence: only well-known OAuth / identity / SSO
 * providers whose authorize/token endpoints agents routinely encounter. Every
 * entry SUPPRESSES the detector, so over-inclusion erodes recall, not precision
 * — but a too-broad list could let a real impostor on a sibling domain slide.
 * Each domain is the provider's own registrable domain (eTLD+1, no scheme/path/
 * www). Subdomains (accounts.google.com, login.microsoftonline.com) are covered
 * automatically because the detector compares eTLD+1.
 */
export const OAUTH_PROVIDER_DOMAINS: ReadonlySet<string> = new Set([
  // Major consumer / platform identity providers.
  "google.com",
  "github.com",
  "microsoft.com",
  "microsoftonline.com", // Azure AD / Entra ID sign-in (login.microsoftonline.com)
  "live.com", // Microsoft account
  "apple.com", // Sign in with Apple
  "facebook.com",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "amazon.com", // Login with Amazon
  "gitlab.com",
  "atlassian.com",
  "slack.com",
  "discord.com",
  "spotify.com",
  // Dedicated identity / SSO / auth platforms.
  "okta.com",
  "auth0.com",
  "onelogin.com",
  "pingidentity.com",
  "duosecurity.com",
]);
