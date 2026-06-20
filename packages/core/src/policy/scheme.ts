import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * Scheme axis. Caller-configured allow/deny on the scheme (lower-cased, no
 * colon). A null scheme (no scheme in the input) is exempt — the axis is
 * skipped, so a schemeless input never emits scheme_denied. Opaque/hostless
 * inputs still carry a scheme (e.g. `javascript`) so scheme policy applies to
 * them. Both lists map to the SAME code; the detail distinguishes deny-list vs
 * not-allow-listed. Distinct from the built-in dangerous_scheme detector.
 */
export function runSchemeAxis(
  ctx: InspectionContext,
  options: InspectOptions,
): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

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
