import type { PolicyAxisDescriptor } from "./types.js";
import { runTldAxis } from "./tld.js";
import { runHostAxis } from "./host.js";
import { runSchemeAxis } from "./scheme.js";
import { runPortAxis } from "./port.js";

/**
 * THE single descriptor source for the 4 policy axes. The dispatcher in
 * `policy.ts` (which iterates these in order) and the recognized-key list in
 * `options.ts` (the flatMap of every descriptor's `optionKeys`) are both DERIVED
 * from this array — add an axis here once and both surfaces pick it up.
 *
 * Lives in its own module (rather than in policy.ts) so `options.ts` can import
 * the descriptors without an options.ts ↔ policy.ts import cycle (policy.ts
 * re-exports `policyConfigured` from options.ts).
 *
 * Order matches today's runtime order exactly and is load-bearing: the findings
 * array order is asserted by tests — TLD → host → scheme → port. Each descriptor
 * reuses the existing axis run function; axis logic is unchanged.
 *
 * Weights and summaries remain owned by `schema/reason-codes.ts`. This registry
 * owns only axis identity, the configuring option keys, the emitted reason
 * codes, and the run wiring. Mirrors the detector `CHECKS` registry.
 */
export const POLICY_AXIS_DESCRIPTORS: readonly PolicyAxisDescriptor[] = [
  {
    id: "tld",
    optionKeys: ["denyTlds", "allowTlds"],
    emits: ["tld_denied", "tld_not_allowlisted"],
    run: runTldAxis,
  },
  {
    id: "host",
    optionKeys: ["denyHosts", "allowHosts"],
    emits: ["host_denied", "host_not_allowlisted"],
    run: runHostAxis,
  },
  {
    id: "scheme",
    optionKeys: ["allowSchemes", "denySchemes"],
    emits: ["scheme_denied"],
    run: runSchemeAxis,
  },
  {
    id: "port",
    optionKeys: ["denyPorts", "denyNonStandardPorts"],
    emits: ["port_denied"],
    run: runPortAxis,
  },
];
