import type { Detector, DetectorFinding } from "./types.js";
import {
  API_BRAND_DOMAINS,
  API_BRAND_LEGITIMATE_DOMAINS,
  API_ROUTE_PREFIXES,
} from "../data/api-brands.js";

/**
 * `api_endpoint_impersonation`. SCORING, weight 0.5. **AGENT-GATED** — emits only
 * when `InspectOptions.agentMode` is true (wired via `agentGated: true` in
 * checks.ts). Like prompt-injection, this targets the LLM-agent / tool-use
 * context: an agent configured to call a provider's API is the party at risk of
 * being pointed at a look-alike API host.
 *
 * ── What fires ──────────────────────────────────────────────────────────────
 * A host that masquerades as a known API provider's endpoint via the SEPARATE
 * api-brands tier (data/api-brands.ts): a host LABEL contains an api-brand TOKEN
 * (`openai`, `anthropic`, …) as an exact, separator-delimited token, WHILE the
 * registrable domain (eTLD+1) is NOT one of that provider's legitimate domains.
 * The canonical shape is the brand glued into a label whose eTLD+1 is unrelated:
 * `api.openai-com.io` — label `openai-com` splits to tokens [`openai`, `com`],
 * the token `openai` is an api-brand, but the registrable domain is `openai-com.io`,
 * which is not `openai.com`.
 *
 * ── Why a separate tier (not the curated brand list) ────────────────────────
 * The match shape differs: an EXACT label-token membership test against the
 * api-brands tier, plus an EXACT eTLD+1 legitimacy check against that provider's
 * pinned domain(s) — not the curated list's edit-distance / keyword machinery.
 *
 * ── Escalation ──────────────────────────────────────────────────────────────
 * Same code, stronger detail: when the path also matches a known API route prefix
 * (`/v1/messages`, `/v1/chat/completions`, `/v1/completions`, `/v1/responses`) the
 * host looks like a real API endpoint AND the path looks like a real API call.
 *
 * ── Precision / performance ─────────────────────────────────────────────────
 * The real provider never fires: if the input's registrable domain is one of the
 * provider's legitimate domains we skip immediately. Matching is set membership
 * over separator-split labels (no substring scans, no regex, no backtracking),
 * well within the <5ms budget. Reuses the pipeline's eTLD+1 facts
 * (`ctx.registrableDomainLower`, `ctx.hostLabels`) — no re-parsing.
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

        const route = matchedApiRoute(ctx.path);
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
