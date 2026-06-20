import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * TLD axis. Caller-configured allow/deny on the TLD — the last label of the
 * public suffix (e.g. `co.uk` → `uk`). IP / hostless inputs have no public
 * suffix and are exempt. Both lists may fire independently when both are
 * configured.
 */
export function runTldAxis(
  ctx: InspectionContext,
  options: InspectOptions,
): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  if (ctx.publicSuffix) {
    const tld = ctx.publicSuffixTld!.toLowerCase();

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

  return findings;
}

/**
 * Normalize a caller-supplied TLD list defensively: strip a leading dot and
 * lower-case each entry so the comparison is bare and case-insensitive.
 */
function normalizeTlds(tlds: string[]): string[] {
  return tlds.map((t) => t.replace(/^\./, "").toLowerCase());
}
