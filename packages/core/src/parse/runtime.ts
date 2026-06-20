import type { InspectOptions } from "../schema/types.js";
import { DEFAULT_MAX_DECODE_DEPTH } from "./decode.js";

/**
 * Per-inspection runtime configuration: the normalized, validated tuning knobs
 * derived once from {@link InspectOptions} and carried on the inspection
 * context. Keeps the raw caller-supplied options out of the hot path and ensures
 * inspection stays total (no throwing on nonsense values).
 */
export interface RuntimeConfig {
  /** Validated maximum number of recursive percent-decode passes. */
  maxDecodeDepth: number;
}

/**
 * Normalize caller {@link InspectOptions} into a {@link RuntimeConfig}. Defaults
 * `maxDecodeDepth` to {@link DEFAULT_MAX_DECODE_DEPTH} when unset, and falls back
 * to the default for any nonsense value (non-finite, negative, or non-integer).
 * Never throws — inspection must be total.
 */
export function normalizeOptions(options: InspectOptions): RuntimeConfig {
  const raw = options.maxDecodeDepth;
  const maxDecodeDepth =
    typeof raw === "number" && Number.isInteger(raw) && raw >= 0
      ? raw
      : DEFAULT_MAX_DECODE_DEPTH;
  return { maxDecodeDepth };
}
