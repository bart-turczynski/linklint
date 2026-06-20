import type { InspectOptions } from "../schema/types.js";

/**
 * Recognized policy option keys. A caller has "configured policy" when any of
 * these is present on the options object. The list is empty in H1 (no axes
 * exist yet); H2–H4 add their field name here as they land, which is what makes
 * {@link policyConfigured} flip to `true` once a caller passes that field.
 *
 * Kept as a typed tuple of `keyof InspectOptions` so a typo or a removed field
 * is caught at compile time.
 */
export const POLICY_OPTION_KEYS = [
  "denyTlds",
  "allowTlds",
  "denyHosts",
  "allowHosts",
  "allowSchemes",
  "denySchemes",
  "denyPorts",
  "denyNonStandardPorts",
] as const satisfies readonly (keyof InspectOptions)[];

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
