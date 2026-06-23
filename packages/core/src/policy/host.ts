import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * Host axis. Caller-configured allow/deny on the registrable domain
 * (eTLD+1). Matching is on `ctx.registrableDomain`, case-insensitive, with a
 * leading dot tolerated and stripped from each list entry. Because the match key
 * is the registrable domain, listing `example.com` covers `example.com` and
 * every subdomain (`sub.example.com` shares registrable domain `example.com`).
 * IP / hostless inputs have no registrable domain and are exempt. Both lists may
 * fire independently when both are configured.
 */
export function runHostAxis(ctx: InspectionContext): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  if (ctx.registrableDomain) {
    const registrable = ctx.registrableDomainLower!;
    const { allowHosts, denyHosts } = ctx.runtime.policy;

    if (denyHosts.set.has(registrable)) {
      findings.push({
        code: "host_denied",
        detail: `Host '${ctx.host}' (registrable domain '${registrable}') is on the caller deny-list`,
      });
    }

    if (allowHosts.configured) {
      if (!allowHosts.set.has(registrable)) {
        findings.push({
          code: "host_not_allowlisted",
          detail: `Host '${ctx.host}' (registrable domain '${registrable}') is not on the caller allow-list ([${allowHosts.values.join(", ")}])`,
        });
      }
    }
  }

  return findings;
}
