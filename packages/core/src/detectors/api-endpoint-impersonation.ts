import type { Detector, DetectorFinding } from "./types.js";
import {
  API_BRAND_DOMAINS,
  API_BRAND_LEGITIMATE_DOMAINS,
  API_ROUTE_PREFIXES,
} from "../data/api-brands.js";

/**
 * `api_endpoint_impersonation`. Agent-gated. Detects API-brand tokens on
 * non-provider registrable domains, requiring an API-looking host label or route
 * before firing. Design rationale and examples live in docs/reason-codes.md.
 */

/**
 * Path-prefix escalation check. Returns the matched route when the path equals a
 * known API route prefix or continues it on a segment boundary (`/v1/messages`,
 * `/v1/messages/123`) — never a partial-label match (`/v1/messagesxyz`). Bounded
 * prefix tests over a fixed route list; no regex, no backtracking.
 */
function matchedApiRoute(path: string): string | null {
  if (!path) return null;
  const lower = path.toLowerCase();
  for (const route of API_ROUTE_PREFIXES) {
    if (lower === route) return route;
    if (lower.startsWith(route) && lower[route.length] === "/") return route;
  }
  return null;
}

/**
 * Corroborating "this host looks like an API endpoint" signal: some host label
 * carries an exact `api`/`apis` token (split on `-`, so `api`, `api-gateway`,
 * `openai-api` all qualify; `myproject`, `stripe-blog` do not). Bounded set
 * membership over already-split labels — no regex, no substring scan.
 */
function hasApiHostLabel(hostLabels: readonly string[]): boolean {
  for (const label of hostLabels) {
    for (const token of label.toLowerCase().split("-")) {
      if (token === "api" || token === "apis") return true;
    }
  }
  return false;
}

export const apiEndpointImpersonation: Detector = {
  id: "api_endpoint_impersonation",
  layer: "lexical",
  agentGated: true,
  run(ctx): DetectorFinding[] {
    if (ctx.isIp) return [];
    if (!ctx.host) return [];

    const registrable = ctx.registrableDomainLower;
    if (!registrable) return [];

    // The real provider, on its own legitimate domain, never fires.
    if (API_BRAND_LEGITIMATE_DOMAINS.has(registrable)) return [];

    // A brand-token match fires only when the URL also looks like an API endpoint.
    const route = matchedApiRoute(ctx.path);
    const apiHostLabel = hasApiHostLabel(ctx.hostLabels);
    if (!route && !apiHostLabel) return [];

    // Find an api-brand token appearing as an exact, separator-delimited token in
    // any host label whose registrable domain is NOT that provider's.
    for (const label of ctx.hostLabels) {
      const lower = label.toLowerCase();
      // Split on `-` so `openai-com` yields the exact token `openai`; a bare label
      // (`openai`) is a single-token split. Empty tokens (leading/trailing `-`)
      // are dropped.
      const tokens = lower.split("-").filter((t) => t !== "");
      for (const token of tokens) {
        const legitDomains = API_BRAND_DOMAINS.get(token);
        if (!legitDomains) continue; // not an api-brand token
        // The api-brand token is present but the eTLD+1 is not the provider's:
        // this host masquerades as the provider's API endpoint.
        if (legitDomains.has(registrable)) continue; // belt-and-suspenders

        const base =
          `host '${ctx.host}' masquerades as the '${token}' API provider — the ` +
          `brand token '${token}' appears in a host label but the registrable domain ` +
          `'${registrable}' is not a legitimate '${token}' domain`;
        return [
          {
            code: "api_endpoint_impersonation",
            detail: route
              ? `${base}; the path also matches a known API route ('${route}'), so it ` +
                `impersonates a real API endpoint`
              : base,
          },
        ];
      }
    }

    return [];
  },
};
