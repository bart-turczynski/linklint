import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * TLD axis. Caller-configured allow/deny on the TLD — the last label of the
 * public suffix (e.g. `co.uk` → `uk`). IP / hostless inputs have no public
 * suffix and are exempt. Both lists may fire independently when both are
 * configured.
 */
export function runTldAxis(ctx: InspectionContext): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  if (ctx.publicSuffix) {
    const tld = ctx.publicSuffixTld!.toLowerCase();
    const { allowTlds, denyTlds } = ctx.runtime.policy;

    if (denyTlds.set.has(tld)) {
      findings.push({
        code: "tld_denied",
        detail: `TLD '.${tld}' is on the caller deny-list`,
      });
    }

    if (allowTlds.configured) {
      if (!allowTlds.set.has(tld)) {
        findings.push({
          code: "tld_not_allowlisted",
          detail: `TLD '.${tld}' is not on the caller allow-list ([${allowTlds.values.join(", ")}])`,
        });
      }
    }
  }

  return findings;
}
