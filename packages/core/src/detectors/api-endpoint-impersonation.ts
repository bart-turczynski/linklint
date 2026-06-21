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
 *
 * ── Precision tightening (V4e corpus tuning) ────────────────────────────────
 * A bare brand-token-on-wrong-eTLD+1 match is too loose on its own: it fires on
 * legitimate brand-owned platform hosts whose eTLD+1 is a sibling domain
 * (`myproject.github.io` — eTLD+1 `github.io`, not `github.com`) and on any host
 * that merely contains a brand word in an unrelated subdomain label
 * (`stripe-blog.example.com`). To impersonate an API ENDPOINT the host must also
 * LOOK like one, so the detector additionally requires a CORROBORATING API
 * signal before firing: either an `api`-ish host label (an exact `api`/`apis`
 * token in some label, split on `-`) OR a path that matches a known API route
 * prefix. `api.openai-com.io` keeps firing (it has the `api` label); the
 * brand-owned-platform / brand-word-subdomain false positives no longer do.
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

    // Corroborating API-endpoint signals (computed once). A brand-token match
    // fires only when at least one is present — see file header.
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
