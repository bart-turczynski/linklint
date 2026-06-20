import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * The policy layer — a separate, caller-configured channel that runs alongside
 * the built-in deception detectors. Unlike detectors, policy never moves the
 * score: its findings carry `layer: "policy"` with `weight: 0` (see
 * {@link InspectOptions} and the `Layer` union), so they annotate without
 * affecting `score`/`severity`.
 *
 * H1 establishes the dispatch machinery only — no axes yet. H2–H4 each add one
 * axis: a new optional field on {@link InspectOptions}, its reason code(s) in
 * the registry, and one axis check appended to {@link runPolicy} below.
 */

/**
 * Recognized policy option keys. A caller has "configured policy" when any of
 * these is present on the options object. The list is empty in H1 (no axes
 * exist yet); H2–H4 add their field name here as they land, which is what makes
 * {@link policyConfigured} flip to `true` once a caller passes that field.
 *
 * Kept as a typed tuple of `keyof InspectOptions` so a typo or a removed field
 * is caught at compile time.
 */
const POLICY_OPTION_KEYS = [
  "denyTlds",
  "allowTlds",
  "denyHosts",
  "allowHosts",
] as const satisfies readonly (keyof InspectOptions)[];

/**
 * Whether the caller has configured any policy axis. False in H1 (no policy
 * fields exist yet); becomes `true` once a caller passes a recognized policy
 * field added in H2–H4. Drives whether `policy` appears in `checksRun`.
 */
export function policyConfigured(options: InspectOptions): boolean {
  return POLICY_OPTION_KEYS.some(
    (key) => options[key] !== undefined,
  );
}

/**
 * Run the policy channel over a parsed context. Returns layer-`policy` findings
 * (weight 0) for every configured axis whose rule the input violates.
 *
 * Pure, synchronous, deterministic, and must never throw — the caller guards it
 * in a try/catch as a backstop (FR-D-13), but the implementation should not
 * rely on that. H1 has no axes, so this returns `[]`; H2–H4 append one axis
 * block each below, reading their field off `options` and pushing
 * `CollectedFinding`s with the axis's policy reason code.
 */
export function runPolicy(
  ctx: InspectionContext,
  options: InspectOptions,
): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  // ── TLD axis (H2) ─────────────────────────────────────────────────────────
  // Caller-configured allow/deny on the TLD — the last label of the public
  // suffix (e.g. `co.uk` → `uk`). IP / hostless inputs have no public suffix and
  // are exempt. Both lists may fire independently when both are configured.
  if (ctx.publicSuffix) {
    const tld = ctx.publicSuffix.split(".").pop()!.toLowerCase();

    if (options.denyTlds && normalizeTlds(options.denyTlds).includes(tld)) {
      findings.push({
        code: "tld_denied",
        detail: `TLD '.${tld}' is on the caller deny-list`,
      });
    }

    if (options.allowTlds) {
      const allow = normalizeTlds(options.allowTlds);
      if (!allow.includes(tld)) {
        findings.push({
          code: "tld_not_allowlisted",
          detail: `TLD '.${tld}' is not on the caller allow-list ([${allow.join(", ")}])`,
        });
      }
    }
  }

  // ── Host axis (H3) ────────────────────────────────────────────────────────
  // Caller-configured allow/deny on the registrable domain (eTLD+1). Matching is
  // on `ctx.registrableDomain`, case-insensitive, with a leading dot tolerated
  // and stripped from each list entry. Because the match key is the registrable
  // domain, listing `example.com` covers `example.com` and every subdomain
  // (`sub.example.com` shares registrable domain `example.com`). IP / hostless
  // inputs have no registrable domain and are exempt. Both lists may fire
  // independently when both are configured.
  if (ctx.registrableDomain) {
    const registrable = ctx.registrableDomain.toLowerCase();

    if (options.denyHosts && normalizeHostList(options.denyHosts).includes(registrable)) {
      findings.push({
        code: "host_denied",
        detail: `Host '${ctx.host}' (registrable domain '${registrable}') is on the caller deny-list`,
      });
    }

    if (options.allowHosts) {
      const allow = normalizeHostList(options.allowHosts);
      if (!allow.includes(registrable)) {
        findings.push({
          code: "host_not_allowlisted",
          detail: `Host '${ctx.host}' (registrable domain '${registrable}') is not on the caller allow-list ([${allow.join(", ")}])`,
        });
      }
    }
  }

  return findings;
}

/**
 * Normalize a caller-supplied TLD list defensively: strip a leading dot and
 * lower-case each entry so the comparison is bare and case-insensitive.
 */
function normalizeTlds(tlds: string[]): string[] {
  return tlds.map((t) => t.replace(/^\./, "").toLowerCase());
}

/**
 * Normalize a caller-supplied host list defensively: strip a leading dot and
 * lower-case each entry so the comparison against the registrable domain is bare
 * and case-insensitive.
 */
function normalizeHostList(hosts: string[]): string[] {
  return hosts.map((h) => h.replace(/^\./, "").toLowerCase());
}
