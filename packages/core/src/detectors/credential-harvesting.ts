import type { Detector, DetectorFinding } from "./types.js";

/**
 * `credential_harvesting`. Agent-gated, INFORMATIONAL (weight 0).
 *
 * Reports one string fact: this URL carries an authorization-code or
 * token-flow shape. Nothing else. Design rationale and examples live in
 * docs/reason-codes.md; the ruling is architecture §1.1 (`LINK-uyoocslu`).
 *
 * ── What was removed, and why (schema `1.10` / weights `1.19`) ──────────────
 * The detector used to suppress itself on `OAUTH_PROVIDER_DOMAINS`, a curated
 * set of ~21 real identity providers, and to score the remainder at 0.35. That
 * is an INVERSE watchlist: the finding was created by a registrable domain's
 * ABSENCE from a hand-kept commercial list, which is the same claim-(b) move
 * `api_endpoint_impersonation` was deleted for (§6.1.4), run in the opposite
 * polarity. The name-never-create rule forbids both polarities.
 *
 * Incompleteness cuts against the allowlist harder than against a watchlist: a
 * self-hosted Keycloak, a Gitea instance and a corporate `login.acme.com` all
 * carry the shape and are all off the list, and whether `auth0.com` is an
 * identity provider next year is a fact about the world.
 *
 * What survives the cut is the shape itself — true of `github.com` as well, and
 * saying so at weight 0 costs nothing. The host is still named in the detail so
 * an agent that wants to compare it against its own list can.
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
                `path contains an OAuth/token-flow endpoint ('${shown}') on host ` +
                `'${ctx.host}' (registrable domain '${registrable}') — an ` +
                `authorization-code / token-flow URL shape`,
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
      `query carries an OAuth/token-flow marker (${marker}) on host '${host}' ` +
      `(registrable domain '${registrable}') — an authorization-code / token-flow URL shape`,
  };
}
