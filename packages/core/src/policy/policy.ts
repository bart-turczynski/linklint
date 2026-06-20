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
  "allowSchemes",
  "denySchemes",
  "denyPorts",
  "denyNonStandardPorts",
] as const satisfies readonly (keyof InspectOptions)[];

/**
 * Standard default port per scheme, used by the `denyNonStandardPorts` axis. A
 * scheme not in this map has no known standard port, so any explicit port on it
 * counts as non-standard.
 */
const STANDARD_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ftp: 21,
  ws: 80,
  wss: 443,
};

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

  // ── Scheme axis (H4) ──────────────────────────────────────────────────────
  // Caller-configured allow/deny on the scheme (lower-cased, no colon). A null
  // scheme (no scheme in the input) is exempt — the axis is skipped, so a
  // schemeless input never emits scheme_denied. Opaque/hostless inputs still
  // carry a scheme (e.g. `javascript`) so scheme policy applies to them. Both
  // lists map to the SAME code; the detail distinguishes deny-list vs
  // not-allow-listed. Distinct from the built-in dangerous_scheme detector.
  if (ctx.scheme) {
    const scheme = ctx.scheme.toLowerCase();

    if (options.denySchemes && normalizeSchemes(options.denySchemes).includes(scheme)) {
      findings.push({
        code: "scheme_denied",
        detail: `scheme '${scheme}' is on the caller deny-list`,
      });
    }

    if (options.allowSchemes) {
      const allow = normalizeSchemes(options.allowSchemes);
      if (!allow.includes(scheme)) {
        findings.push({
          code: "scheme_denied",
          detail: `scheme '${scheme}' is not on the caller allow-list ([${allow.join(", ")}])`,
        });
      }
    }
  }

  // ── Port axis (H4) ────────────────────────────────────────────────────────
  // Caller-configured deny on the port, evaluated only when an explicit port is
  // present (ctx.port non-null). `denyPorts` blocks enumerated ports;
  // `denyNonStandardPorts` blocks any explicit port that is not the scheme's
  // standard default (see STANDARD_PORTS). At most one port_denied is emitted
  // per input — if both conditions hit, the deny-list reason wins (deduped).
  if (ctx.port !== null) {
    const port = ctx.port;
    if (options.denyPorts && options.denyPorts.includes(port)) {
      findings.push({
        code: "port_denied",
        detail: `port ${port} is on the caller deny-list`,
      });
    } else if (options.denyNonStandardPorts) {
      const scheme = ctx.scheme ? ctx.scheme.toLowerCase() : null;
      const standard = scheme !== null ? STANDARD_PORTS[scheme] : undefined;
      if (standard === undefined || port !== standard) {
        const expected =
          standard !== undefined
            ? ` (expected ${standard})`
            : scheme !== null
              ? ` (no standard port for scheme '${scheme}')`
              : "";
        findings.push({
          code: "port_denied",
          detail: `port ${port} is non-standard for scheme '${scheme ?? "?"}'${expected}`,
        });
      }
    }
  }

  return findings;
}

/**
 * Normalize a caller-supplied scheme list defensively: strip leading/trailing
 * colons and lower-case each entry so the comparison against the parsed scheme
 * is bare and case-insensitive.
 */
function normalizeSchemes(schemes: string[]): string[] {
  return schemes.map((s) => s.replace(/^:+|:+$/g, "").toLowerCase());
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
