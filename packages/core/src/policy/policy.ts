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
 * What one {@link runPolicy} call actually did, per axis.
 *
 * Findings alone cannot report the channel honestly: a caller must be able to
 * tell "no axis matched" from "the axis that would have matched threw"
 * (LINK-ymprmvhr). This is the shape that carries the difference out.
 */
export interface PolicyOutcome {
  /** Concatenated findings of the axes that completed, in registry order. */
  readonly findings: CollectedFinding[];
  /** Registry ids of the axes that threw, in registry order. Usually empty. */
  readonly skippedAxes: string[];
  /**
   * Whether at least one axis completed. False only when every axis threw —
   * the single case in which the channel produced no verdict at all and so
   * must not claim in `checksRun` to have run.
   */
  readonly anyAxisRan: boolean;
}

/**
 * Run the policy channel over a parsed context. Returns layer-`policy` findings
 * (weight 0) for every configured axis whose rule the input violates, together
 * with the ids of any axes that failed.
 *
 * Pure, synchronous, deterministic, and must never throw — the caller guards it
 * in a try/catch as a backstop (FR-D-13), but the implementation should not
 * rely on that. Iterates {@link POLICY_AXIS_DESCRIPTORS} in order and
 * concatenates their findings. The registry order is load-bearing: the findings
 * array order is asserted by tests — TLD → host → scheme → port.
 *
 * THE GUARD IS PER AXIS, not around the loop (LINK-ymprmvhr). `inspect()`'s
 * detector and structural loops have always caught *inside* the loop, so one
 * failing check costs exactly one check; the policy channel was guarded only at
 * its call site, so a single throwing axis discarded the findings of the axes
 * that had already succeeded. Containing the failure here is also what lets the
 * skip name the axis (`policy:<id>`) rather than condemn the whole channel.
 *
 * Both the axis call and the spread of its result sit inside the guard: an axis
 * that returns a non-array is a failure of that axis, not of the dispatcher.
 *
 * The run functions are resolved from the descriptors PER CALL rather than
 * snapshotted into a module-level array at import time (LINK-voqqhxgj). Two
 * reasons, one of them not about testing:
 *
 *  - The registry becomes the single source of truth at call time, not merely
 *    at first import. A module-level `.map()` silently pins whatever `run` the
 *    descriptor happened to hold when this module was first loaded.
 *  - It gives the FR-D-13 policy catch an injection seam. That catch is
 *    otherwise unreachable from a test: no malformed option value reaches it
 *    (the axes are defensive and handle wrong-typed config rather than
 *    throwing), and a snapshotted array cannot be spied on, because it holds
 *    bare function references rather than the objects that own them.
 *    `DETECTORS` and `STRUCTURAL_SCANS` are spyable precisely because their
 *    loops re-read a `run` PROPERTY on each pass; this now matches them.
 *
 * The per-call property lookup over a 4-element array is not measurable against
 * the axis work itself.
 */
export function runPolicy(ctx: InspectionContext): PolicyOutcome {
  const findings: CollectedFinding[] = [];
  const skippedAxes: string[] = [];
  let completed = 0;
  for (const descriptor of POLICY_AXIS_DESCRIPTORS) {
    const id = descriptor.id;
    try {
      findings.push(...descriptor.run(ctx));
      completed += 1;
    } catch {
      // One axis's failure must cost one axis (FR-D-13). The id is read before
      // the guard so that recording the skip cannot itself throw.
      skippedAxes.push(id);
    }
  }
  return { findings, skippedAxes, anyAxisRan: completed > 0 };
}
