import type { Detector, DetectorFinding } from "./types.js";
import { OAUTH_PROVIDER_DOMAINS } from "../data/oauth-providers.js";

/**
 * `credential_harvesting`. Agent-gated. Detects OAuth/token-flow URL shapes on
 * non-allowlisted registrable domains. Design rationale and examples live in
 * docs/reason-codes.md.
 */

/**
 * OAuth / token-flow path markers, lowercase and segment-boundary matched.
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
 * Token-flow query parameter names, matched exactly and case-insensitively.
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

/** Parse the raw query into lowercase parameter names and values. */
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
