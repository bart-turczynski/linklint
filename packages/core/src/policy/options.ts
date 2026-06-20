import type { InspectOptions } from "../schema/types.js";
import { POLICY_AXIS_DESCRIPTORS } from "./axes.js";

/**
 * Recognized policy option keys. A caller has "configured policy" when any of
 * these is present on the options object. DERIVED from
 * {@link POLICY_AXIS_DESCRIPTORS} — the flatMap of every descriptor's
 * `optionKeys`, in registry order — so the recognized-key set tracks the axes
 * automatically as they grow and cannot drift from the registry.
 *
 * Typed as `readonly (keyof InspectOptions)[]` so a typo or a removed field is
 * caught at compile time (the descriptors' `optionKeys` are themselves
 * `keyof InspectOptions`).
 */
export const POLICY_OPTION_KEYS: readonly (keyof InspectOptions)[] =
  POLICY_AXIS_DESCRIPTORS.flatMap((descriptor) => descriptor.optionKeys);

/**
 * Whether the caller has configured any policy axis. False when no policy
 * fields exist; becomes `true` once a caller passes a recognized policy
 * field. Drives whether `policy` appears in `checksRun`.
 */
export function policyConfigured(options: InspectOptions): boolean {
  return POLICY_OPTION_KEYS.some(
    (key) => options[key] !== undefined,
  );
}
