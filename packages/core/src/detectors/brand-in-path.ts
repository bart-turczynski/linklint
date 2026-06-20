import type { Detector } from "./types.js";
import { isBrandKeyword } from "../data/brands.js";

/**
 * J7 — `brand_in_path` (Epic J). SCORING, low weight (0.2).
 *
 * Promotes a brand reference planted in the PATH/QUERY of an UNRELATED host from
 * the info-only `confusable_in_path` annotation to a low scoring signal. The lure
 * is `https://evil.com/paypal.com/login`: the destination domain is `evil.com`,
 * but the URL "contains" `paypal.com`, so a skimming user trusts it.
 *
 * Distinct from `confusable_in_path` (FR-D-12, weight 0, which flags confusable
 * CHARACTERS in the path) — this flags a brand KEYWORD in the path.
 *
 * Precision-first (SC-2). Fires only on the two phishing-shaped patterns, and
 * only when the brand does NOT appear in the host (a brand in the host is a
 * different attack, owned by `embedded_domain_in_subdomain` / Epic G):
 *   - **domain-shaped** — a path/query token `<brand>.<tld>` (`/paypal.com/`,
 *     `?next=paypal.com`). A literal brand domain as a path token is rare in
 *     legitimate URLs.
 *   - **credential flow** — a bare `<brand>` path segment together with a
 *     credential-flow word (`login`, `signin`, `verify`, …): `/paypal/login`.
 *     The credential context is required so an ordinary `/amazon/dp/...` style
 *     path does not flag.
 *
 * Uses the SEED brand list in `data/brands.ts`; Epic G replaces it with the
 * authoritative, expandable list and adds the host-side brand escalations.
 */

const CREDENTIAL_WORDS = new Set([
  "login",
  "signin",
  "sign-in",
  "logon",
  "account",
  "accounts",
  "secure",
  "security",
  "verify",
  "verification",
  "confirm",
  "update",
  "billing",
  "payment",
  "password",
  "auth",
  "authenticate",
  "webscr",
  "recover",
  "unlock",
]);

const DOMAIN_SHAPED = /^([a-z0-9-]+)\.[a-z]{2,}(?:\.[a-z]{2,})?$/;

/** Split a path/query string into lowercase alphanumeric-ish tokens. */
function tokenize(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[/?&=#;,\s]+/)
    .filter((t) => t !== "");
}

export const brandInPath: Detector = {
  id: "brand_in_path",
  layer: "lexical",
  run(ctx) {
    if (ctx.path === "" && !ctx.query) return [];

    const hostLower = ctx.host.toLowerCase();
    const tokens = [...tokenize(ctx.path), ...(ctx.query ? tokenize(ctx.query) : [])];
    if (tokens.length === 0) return [];

    const hasCredentialContext = tokens.some((t) => CREDENTIAL_WORDS.has(t));

    const domainShaped = new Set<string>();
    const credentialFlow = new Set<string>();
    for (const token of tokens) {
      const m = DOMAIN_SHAPED.exec(token);
      if (m && isBrandKeyword(m[1]!)) {
        const brand = m[1]!;
        if (!hostLower.includes(brand)) domainShaped.add(token);
        continue;
      }
      if (isBrandKeyword(token) && hasCredentialContext && !hostLower.includes(token)) {
        credentialFlow.add(token);
      }
    }

    if (domainShaped.size === 0 && credentialFlow.size === 0) return [];

    const parts: string[] = [];
    if (domainShaped.size > 0) {
      parts.push(`brand domain(s) in the path/query: ${[...domainShaped].join(", ")}`);
    }
    if (credentialFlow.size > 0) {
      parts.push(`brand keyword(s) in a credential-flow path: ${[...credentialFlow].join(", ")}`);
    }
    return [
      {
        code: "brand_in_path",
        detail:
          `the real host is '${ctx.host}', but a brand reference is planted in the path/query — ${parts.join("; ")}`,
      },
    ];
  },
};
