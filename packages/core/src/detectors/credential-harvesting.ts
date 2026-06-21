import type { Detector, DetectorFinding } from "./types.js";
import { OAUTH_PROVIDER_DOMAINS } from "../data/oauth-providers.js";

/**
 * `credential_harvesting`. SCORING, weight 0.35. **AGENT-GATED** — emits only
 * when `InspectOptions.agentMode` is true (wired via `agentGated: true` in
 * checks.ts). Like the other gated detectors, this targets the LLM-agent /
 * tool-use context: an agent that follows a link carrying an OAuth / token flow
 * is the party at risk of being walked through a credential-phishing or
 * token-exfiltration handshake on an impostor host.
 *
 * ── What fires ──────────────────────────────────────────────────────────────
 * An OAuth / token-flow URL SHAPE on a NON-allowlisted host. Two signal classes:
 *   - **path markers** — an OAuth authorize/token segment sequence
 *     (`/oauth/authorize`, `/oauth/token`, `/oauth2/authorize`,
 *     `/login/oauth/authorize`, `/connect/authorize`, …).
 *   - **query markers** — token-flow parameters: `redirect_uri=`,
 *     `access_token=`, `client_secret=`, `response_type=token`, or `code=`
 *     combined with `client_id=` (the authorization-code callback pair).
 *
 * This SEPARATE reason code stacks naturally with brand / api impersonation —
 * the scoring is a probabilistic OR, so two reasons compound on their own. The
 * detector emits only its own code; it never special-cases stacking.
 *
 * ── CRITICAL precision constraint: non-allowlisted hosts only ───────────────
 * These markers are PERFECTLY LEGITIMATE on real OAuth providers
 * (accounts.google.com/oauth/authorize, github.com/login/oauth/authorize). The
 * detector therefore fires ONLY when the OAuth/token shape is present AND the
 * registrable domain (eTLD+1) is NOT on the conservative OAuth-provider
 * allowlist (data/oauth-providers.ts). The real provider, on its own domain (any
 * subdomain), never fires.
 *
 * ── Precision / performance ─────────────────────────────────────────────────
 * Matching is bounded: a fixed set of path-marker phrases tested over a
 * normalized lowercase path, and exact parameter-NAME membership tests over the
 * split query (no substring scans of values, no regex backtracking) — well
 * within the <5ms budget. Reuses the pipeline's eTLD+1 facts
 * (`ctx.registrableDomainLower`) and raw `path` / `query` — no re-parsing.
 */

/**
 * OAuth / token-flow path markers, lowercase. Matched as a contiguous segment
 * SUBSTRING of the normalized path (segments joined by `/`, wrapped so a marker
 * matches only on segment boundaries — `/oauth/authorize` matches but
 * `/myoauth/authorizenow` does not). Conservative, fixed list — every entry is a
 * canonical authorize/token endpoint shape.
 */
const OAUTH_PATH_MARKERS: readonly string[] = [
  "/oauth/authorize/",
  "/oauth/token/",
  "/oauth2/authorize/",
  "/oauth2/token/",
  "/login/oauth/authorize/",
  "/login/oauth/access_token/",
  "/connect/authorize/",
  "/connect/token/",
];

/**
 * Token-flow query parameter NAMES, lowercase. Each is, on its own, a strong
 * marker of an OAuth / token handshake. Compared case-insensitively against the
 * EXACT parameter name (never a substring scan).
 */
const TOKEN_FLOW_PARAMS: ReadonlySet<string> = new Set([
  "redirect_uri",
  "access_token",
  "client_secret",
]);

/**
 * Normalize the raw path for marker matching: lowercase, ensure a single leading
 * `/`, and append a trailing `/` so every marker (also `/`-wrapped) anchors on
 * segment boundaries.
 */
function normalizedPath(path: string): string {
  let p = path.toLowerCase();
  if (!p.startsWith("/")) p = `/${p}`;
  if (!p.endsWith("/")) p = `${p}/`;
  return p;
}

/** Parse the raw query (no leading `?`) into the set of lowercase parameter
 *  names present and a name→value map (values lowercased) for value checks. */
function queryParams(query: string): { names: Set<string>; values: Map<string, string> } {
  const names = new Set<string>();
  const values = new Map<string, string>();
  for (const pair of query.split("&")) {
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    const rawKey = eq === -1 ? pair : pair.slice(0, eq);
    const rawValue = eq === -1 ? "" : pair.slice(eq + 1);
    const key = rawKey.toLowerCase();
    if (key === "") continue;
    names.add(key);
    if (!values.has(key)) values.set(key, rawValue.toLowerCase());
  }
  return { names, values };
}

export const credentialHarvesting: Detector = {
  id: "credential_harvesting",
  layer: "lexical",
  agentGated: true,
  run(ctx): DetectorFinding[] {
    if (ctx.isIp) return [];
    if (!ctx.host) return [];

    const registrable = ctx.registrableDomainLower;
    if (!registrable) return [];

    // The real OAuth / identity provider, on its own domain, never fires.
    if (OAUTH_PROVIDER_DOMAINS.has(registrable)) return [];

    // 1. OAuth authorize/token path marker.
    if (ctx.path) {
      const path = normalizedPath(ctx.path);
      for (const marker of OAUTH_PATH_MARKERS) {
        if (path.includes(marker)) {
          // strip wrapping slashes for the human detail
          const shown = marker.slice(1, -1);
          return [
            {
              code: "credential_harvesting",
              detail:
                `path contains an OAuth/token-flow endpoint ('${shown}') on the ` +
                `non-allowlisted host '${ctx.host}' (registrable domain '${registrable}' ` +
                `is not a known OAuth/identity provider) — a credential-phishing URL shape`,
            },
          ];
        }
      }
    }

    // 2. Token-flow query markers.
    if (ctx.query) {
      const { names, values } = queryParams(ctx.query);

      for (const param of TOKEN_FLOW_PARAMS) {
        if (names.has(param)) {
          return [tokenFlowFinding(ctx.host, registrable, `the '${param}' parameter`)];
        }
      }

      // response_type=token (implicit token grant).
      if (values.get("response_type") === "token") {
        return [tokenFlowFinding(ctx.host, registrable, "'response_type=token' (implicit grant)")];
      }

      // code= combined with client_id= (the authorization-code callback pair).
      if (names.has("code") && names.has("client_id")) {
        return [
          tokenFlowFinding(ctx.host, registrable, "the 'code'+'client_id' authorization-code pair"),
        ];
      }
    }

    return [];
  },
};

/** Build a token-flow query-marker finding with a uniform detail shape. */
function tokenFlowFinding(host: string, registrable: string, marker: string): DetectorFinding {
  return {
    code: "credential_harvesting",
    detail:
      `query carries an OAuth/token-flow marker (${marker}) on the non-allowlisted host ` +
      `'${host}' (registrable domain '${registrable}' is not a known OAuth/identity provider) ` +
      `— a credential-phishing / token-exfiltration URL shape`,
  };
}
