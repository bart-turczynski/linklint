import type { InspectOptions } from "../schema/types.js";
import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

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
