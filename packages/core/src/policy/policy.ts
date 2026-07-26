import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";
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
 * Run the policy channel over a parsed context. Returns layer-`policy` findings
 * (weight 0) for every configured axis whose rule the input violates.
 *
 * Pure, synchronous, deterministic, and must never throw — the caller guards it
 * in a try/catch as a backstop (FR-D-13), but the implementation should not
 * rely on that. Iterates {@link POLICY_AXIS_DESCRIPTORS} in order and
 * concatenates each axis's findings. The registry order is load-bearing: the
 * findings array order is asserted by tests — TLD → host → scheme → port.
 *
 * The run functions are resolved from the descriptors PER CALL rather than
 * snapshotted into a module-level array at import time (LINK-voqqhxgj). Two
 * reasons, one of them not about testing:
 *
 *  - The registry becomes the single source of truth at call time, not merely
 *    at first import. A module-level `.map()` silently pins whatever `run` the
 *    descriptor happened to hold when this module was first loaded.
 *  - It gives the FR-D-13 policy catch in `inspect()` an injection seam. That
 *    catch is otherwise unreachable from a test: no malformed option value
 *    reaches it (the axes are defensive and handle wrong-typed config rather
 *    than throwing), and a snapshotted array cannot be spied on, because it
 *    holds bare function references rather than the objects that own them.
 *    `DETECTORS` and `STRUCTURAL_SCANS` are spyable precisely because their
 *    loops re-read a `run` PROPERTY on each pass; this now matches them.
 *
 * The per-call property lookup over a 4-element array is not measurable against
 * the axis work itself.
 */
export function runPolicy(ctx: InspectionContext): CollectedFinding[] {
  const findings: CollectedFinding[] = [];
  for (const descriptor of POLICY_AXIS_DESCRIPTORS) {
    findings.push(...descriptor.run(ctx));
  }
  return findings;
}
