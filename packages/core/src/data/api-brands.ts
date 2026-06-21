/**
 * API-provider brand tier — a SEPARATE, conservative watchlist distinct from the
 * curated brand watchlist in `brands.ts`. It exists solely for the agent-gated
 * `api_endpoint_impersonation` detector (V4b): hosts that masquerade as a known
 * API provider's endpoint by gluing the provider's brand token into a label whose
 * registrable domain is NOT the real provider (e.g. `api.openai-com.io`).
 *
 * This is deliberately NOT folded into `BRAND_WATCHLIST`:
 *   - The matching shape is different — here a brand TOKEN appears as an exact,
 *     separator-delimited host label (`api`, `openai`, `openai-com`) rather than
 *     an edit-distance near-miss of a registrable domain.
 *   - The legitimacy test is an exact eTLD+1 match against the provider's own
 *     registrable domain(s), so each entry pins its real domain(s) explicitly.
 *
 * Kept SMALL and high-confidence: only well-known AI/LLM + a couple of obvious
 * developer-API providers whose `api.` endpoints are routinely fetched by agents.
 * Every token here widens what the detector keys on, so precision comes first.
 *
 * Entries are normalized: lowercase brand token, lowercase legitimate registrable
 * domains (eTLD+1, no scheme/path/www).
 */

/** A single API-provider brand on the api-brands tier. */
export interface ApiBrandEntry {
  /**
   * The provider brand token, lowercase. Matched as an EXACT, separator-delimited
   * host label component (split on `-`), never a substring scan.
   */
  readonly token: string;
  /**
   * The provider's legitimate registrable domain(s), lowercase (eTLD+1). A host
   * whose registrable domain is one of these is the real provider and never
   * fires. Multiple entries allow ccTLD / alternate official domains.
   */
  readonly domains: readonly string[];
}

/**
 * The api-brands watchlist. Order is not significant. Conservative by design.
 */
export const API_BRAND_WATCHLIST: readonly ApiBrandEntry[] = [
  { token: "openai", domains: ["openai.com"] },
  { token: "anthropic", domains: ["anthropic.com"] },
  { token: "googleapis", domains: ["googleapis.com"] },
  { token: "cohere", domains: ["cohere.com", "cohere.ai"] },
  { token: "mistral", domains: ["mistral.ai"] },
  { token: "huggingface", domains: ["huggingface.co"] },
  { token: "stripe", domains: ["stripe.com"] },
  { token: "twilio", domains: ["twilio.com"] },
  { token: "sendgrid", domains: ["sendgrid.com"] },
  { token: "github", domains: ["github.com"] },
];

/**
 * Map from a provider brand token to its legitimate registrable domains, for O(1)
 * lookups. Derived from `API_BRAND_WATCHLIST` so the watchlist is the single
 * source of truth.
 */
export const API_BRAND_DOMAINS: ReadonlyMap<string, ReadonlySet<string>> = new Map(
  API_BRAND_WATCHLIST.map((b) => [b.token, new Set(b.domains)] as const),
);

/**
 * All legitimate API-provider registrable domains, deduped — the union of every
 * entry's `domains`. Used to short-circuit on a real provider host.
 */
export const API_BRAND_LEGITIMATE_DOMAINS: ReadonlySet<string> = new Set(
  API_BRAND_WATCHLIST.flatMap((b) => [...b.domains]),
);

/**
 * Known API route prefixes (normalized leading path segments) that, when present
 * alongside an impersonating host, escalate the finding — the host looks like a
 * real API endpoint AND the path looks like a real API call.
 */
export const API_ROUTE_PREFIXES: readonly string[] = [
  "/v1/messages",
  "/v1/chat/completions",
  "/v1/completions",
  "/v1/responses",
];
