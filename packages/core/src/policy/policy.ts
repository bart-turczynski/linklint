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
const POLICY_OPTION_KEYS = [] as const satisfies readonly (keyof InspectOptions)[];

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
  _ctx: InspectionContext,
  _options: InspectOptions,
): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  // H2–H4: each axis appends here, e.g.
  //   findings.push(...checkDenyTlds(ctx, options));
  // Axis checks read their field off `options`, are individually total, and
  // emit policy reason codes (layer "policy", weight 0).

  return findings;
}
