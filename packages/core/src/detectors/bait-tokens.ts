import type { Detector, DetectorFinding, InspectionContext } from "./types.js";

/**
 * G4 — `bait_tokens` (Epic G). SCORING, LOW weight (0.15).
 *
 * A cheap lexical corroborating signal: the density of phishing-BAIT keywords
 * (`secure`, `verify`, `account`, `login`, `signin`, `update`, `wallet`,
 * `confirm`, `password`, `billing`, `suspended`, `unlock`, `authenticate`,
 * `recover`, …) stacked across the HOST and PATH. Phishing lures pile up
 * reassuring/urgent credential words — `secure-account-verify-login.com`,
 * `update-billing.example.tk/confirm/password` — to look official.
 *
 * ── On its own this is WEAK (the whole-game precision constraint) ───────────
 * Legitimate login/account pages routinely carry one or two of these tokens
 * (`accounts.google.com/signin`, a bank's `/account/login`,
 * `login.microsoftonline.com`). So a single bait token MUST NEVER fire, and the
 * weight is deliberately LOW (0.15, the risky_tld / excessive_subdomain_depth
 * band): this corroborates G2/G3 brand checks, it is never decisive alone.
 *
 * ── Threshold (the precision lever) ─────────────────────────────────────────
 * Legit sites stack bait words in the PATH all the time (`/account/security/
 * signin`) but rarely in the HOST. So we weight host-side bait more heavily and
 * fire only on a HIGH density:
 *   - >= 2 DISTINCT bait tokens in the HOST labels, OR
 *   - >= 3 DISTINCT bait tokens across host + path/query combined.
 * A lone bait token, or a couple of path-only bait words on a real login page,
 * stays quiet. Tuned so the full existing corpus stays precision=1, recall=1.
 *
 * ── Curated lexicon ─────────────────────────────────────────────────────────
 * A small static `ReadonlySet<string>` inline in this file — the same judgment
 * as ascii-confusables.ts: an intrinsic, hand-curated micro-lexicon, not
 * external/evolving curated data, so no `dataVersions` pin. If this set grows
 * into a maintained, frequently-revised list it would warrant a version pin —
 * flag at that point rather than pinning a 14-word set now.
 *
 * `layer: "lexical"`. Skips IP hosts and host-less inputs.
 */

/** Phishing-bait keyword micro-lexicon (lowercase). Small + static — no version pin. */
const BAIT_TOKENS: ReadonlySet<string> = new Set([
  "secure",
  "verify",
  "account",
  "update",
  "signin",
  "login",
  "logon",
  "wallet",
  "confirm",
  "password",
  "passwd",
  "billing",
  "suspended",
  "unlock",
  "authenticate",
  "recover",
  "validation",
]);

/** Distinct bait tokens in HOST labels (split on `-` and the `.` label boundary). */
const HOST_BAIT_THRESHOLD = 2;
/** Distinct bait tokens across host + path/query combined. */
const TOTAL_BAIT_THRESHOLD = 3;

/** Split a string into lowercase alphanumeric tokens on common separators. */
function tokenize(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t !== "");
}

/** Collect the DISTINCT bait tokens present in a token list. */
function baitIn(tokens: Iterable<string>): Set<string> {
  const found = new Set<string>();
  for (const t of tokens) {
    if (BAIT_TOKENS.has(t)) found.add(t);
  }
  return found;
}

export const baitTokens: Detector = {
  id: "bait_tokens",
  layer: "lexical",
  run(ctx: InspectionContext): DetectorFinding[] {
    if (ctx.isIp || !ctx.host) return [];

    // Host-side bait (weighted more heavily — legit hosts rarely stack these).
    const hostTokens = ctx.hostLabels.flatMap((label) => tokenize(label));
    const hostBait = baitIn(hostTokens);

    // Path + query bait.
    const pathQuery = `${ctx.path}${ctx.query ? `?${ctx.query}` : ""}`;
    const pathBait = baitIn(tokenize(pathQuery));

    const total = new Set<string>([...hostBait, ...pathBait]);

    const hostHit = hostBait.size >= HOST_BAIT_THRESHOLD;
    const totalHit = total.size >= TOTAL_BAIT_THRESHOLD;
    if (!hostHit && !totalHit) return [];

    const hostList = [...hostBait].sort();
    const pathOnly = [...pathBait].filter((t) => !hostBait.has(t)).sort();
    const where: string[] = [];
    if (hostList.length > 0) where.push(`host (${hostList.join(", ")})`);
    if (pathOnly.length > 0) where.push(`path (${pathOnly.join(", ")})`);

    return [
      {
        code: "bait_tokens",
        detail:
          `host/path stacks ${total.size} distinct phishing-bait keyword(s) — ` +
          `${where.join(", ")} — high bait-token density`,
      },
    ];
  },
};
