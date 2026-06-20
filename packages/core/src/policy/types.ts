import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";
import type { ReasonCode } from "../schema/reason-codes.js";

/**
 * A single policy axis: a pure function that reads its field(s) off `options`
 * and returns the layer-`policy` findings (weight 0) the input violates for
 * that axis. Axes are deterministic, synchronous, and must never throw. The
 * dispatcher in `policy.ts` iterates the configured axes and concatenates their
 * findings in a fixed order.
 */
export type PolicyAxis = (
  ctx: InspectionContext,
  options: InspectOptions,
) => CollectedFinding[];

/**
 * THE single descriptor for a policy axis — the source of truth for an axis's
 * identity, the option keys that configure it, the reason codes it can emit, and
 * its run thunk. `POLICY_AXIS_DESCRIPTORS` (axes.ts) is the one registry; the
 * dispatcher in `policy.ts` and the recognized-key list in `options.ts` are both
 * DERIVED from it, so policy metadata cannot silently drift as axes grow.
 *
 * Weights and summaries remain owned by `schema/reason-codes.ts`; this registry
 * owns only axis identity, the configuring option keys, the emitted codes, and
 * the run wiring. Mirrors the detector `CHECKS` registry.
 */
export interface PolicyAxisDescriptor {
  id: string;
  optionKeys: readonly (keyof InspectOptions)[];
  emits: readonly ReasonCode[];
  run: PolicyAxis;
}
