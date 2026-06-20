import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";
import type { PolicyAxis } from "./types.js";
import { POLICY_AXIS_DESCRIPTORS } from "./axes.js";

export { policyConfigured } from "./options.js";

/**
 * The policy layer — a separate, caller-configured channel that runs alongside
 * the built-in deception detectors. Unlike detectors, policy never moves the
 * score: its findings carry `layer: "policy"` with `weight: 0` (see
 * {@link InspectOptions} and the `Layer` union), so they annotate without
 * affecting `score`/`severity`.
 *
 * Each axis lives in its own module under `policy/` (tld, host, scheme, port);
 * this file is the dispatcher that iterates the axes in a fixed order and
 * concatenates their findings.
 */

/**
 * The configured policy axes' run functions, in evaluation order. DERIVED from
 * {@link POLICY_AXIS_DESCRIPTORS} — the registry is the single source of truth.
 * The findings array order is asserted by tests, so the registry order is
 * load-bearing: TLD → host → scheme → port.
 */
const POLICY_AXES: readonly PolicyAxis[] = POLICY_AXIS_DESCRIPTORS.map(
  (descriptor) => descriptor.run,
);

/**
 * Run the policy channel over a parsed context. Returns layer-`policy` findings
 * (weight 0) for every configured axis whose rule the input violates.
 *
 * Pure, synchronous, deterministic, and must never throw — the caller guards it
 * in a try/catch as a backstop (FR-D-13), but the implementation should not
 * rely on that. Iterates {@link POLICY_AXES} in order and concatenates each
 * axis's findings.
 */
export function runPolicy(
  ctx: InspectionContext,
  options: InspectOptions,
): CollectedFinding[] {
  const findings: CollectedFinding[] = [];
  for (const axis of POLICY_AXES) {
    findings.push(...axis(ctx, options));
  }
  return findings;
}
