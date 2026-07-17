import type { InspectOptions, Reason } from "../schema/types.js";
import type { SuppressionRule } from "../parse/runtime.js";
import { toUnicode } from "../unicode/idna.js";

/**
 * Caller false-positive escape hatch — the general form of the single-heuristic
 * `idnPolicy`/`idnAllowlist` opt-out, applied to EVERY reason code
 * (docs/architecture.md §9). A caller supplies {@link InspectOptions.suppressReasons};
 * a matched reason is ANNOTATED (`suppressed: true`) and its scoring weight zeroed
 * so `aggregate` (which already skips weight-0 reasons) ignores it. The reason
 * STAYS in `reasons[]` — linklint is never silently clean.
 *
 * This module is the single shared predicate used by BOTH the sync `inspect()`
 * path (via `buildOkResult`) and `inspectAsync`'s re-aggregation, so an
 * enricher-layer reason is suppressible by exactly the same mechanism.
 */

/**
 * Whether the caller configured the suppression escape hatch. Mirrors
 * `policyConfigured`: true once `suppressReasons` is present (even `[]`), so the
 * `suppression` marker in `checksRun` is honest that a caller escape hatch was
 * wired — never silently. False (and thus byte-for-byte unchanged output) when
 * the field is absent.
 */
export function suppressConfigured(options: InspectOptions): boolean {
  return options.suppressReasons !== undefined;
}

/**
 * Canonicalize an input's registrable domain into the form suppression `host`
 * rules are matched against — Unicode, lower-cased (as `idn_host` does for
 * `idnAllowlist`). `null` for IP / hostless inputs, which never match a
 * host-scoped rule.
 */
export function suppressionHostContext(registrableDomain: string | null): string | null {
  if (!registrableDomain) return null;
  return toUnicode(registrableDomain).toLowerCase();
}

/**
 * Apply suppression `rules` to `reasons` for an input whose registrable domain
 * canonicalizes to `hostContext`. A rule matches a reason when its `code` equals
 * the reason's `code` AND either the rule has no `host` (global) or its `host`
 * equals `hostContext`. A matched reason is returned annotated `suppressed: true`
 * with `weight: 0` (excluded from scoring); unmatched reasons are returned
 * unchanged. With no rules the input array is returned as-is, so the default
 * path is untouched.
 */
export function applySuppressions(
  reasons: Reason[],
  rules: readonly SuppressionRule[],
  hostContext: string | null,
): Reason[] {
  if (rules.length === 0) return reasons;
  return reasons.map((reason) => {
    const suppressed = rules.some(
      (rule) =>
        rule.code === reason.code && (rule.host === null || rule.host === hostContext),
    );
    return suppressed ? { ...reason, weight: 0, suppressed: true } : reason;
  });
}
