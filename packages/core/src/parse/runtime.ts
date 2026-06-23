import type { InspectOptions } from "../schema/types.js";
import { DEFAULT_MAX_DECODE_DEPTH } from "./decode.js";
import { toUnicode } from "../unicode/idna.js";

/**
 * Per-inspection runtime configuration: the normalized, validated tuning knobs
 * derived once from {@link InspectOptions} and carried on the inspection
 * context. Keeps the raw caller-supplied options out of the hot path and ensures
 * inspection stays total (no throwing on nonsense values).
 */
export interface RuntimeConfig {
  /** Validated maximum number of recursive percent-decode passes. */
  maxDecodeDepth: number;
  /** IDN handling: `"block"` (default) flags non-ASCII registrable domains; `"allow"` exempts them. */
  idnPolicy: "block" | "allow";
  /** Normalized IDN allow-list: lower-cased, leading-dot-stripped registrable domains exempt under `"block"`. */
  idnAllowlist: ReadonlySet<string>;
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
  // IDN handling defaults to "block"; any value other than the explicit "allow"
  // opt-out (including unset/nonsense) is treated as "block". Never throws.
  const idnPolicy = options.idnPolicy === "allow" ? "allow" : "block";
  // Canonicalize allow-list entries to their Unicode, lower-cased form so a
  // user's "münchen.de" matches a punycode (xn--) input and vice-versa.
  const idnAllowlist = new Set<string>(
    (Array.isArray(options.idnAllowlist) ? options.idnAllowlist : [])
      .filter((d): d is string => typeof d === "string")
      .map((d) => toUnicode(d.replace(/^\./, "")).toLowerCase()),
  );
  return { maxDecodeDepth, idnPolicy, idnAllowlist };
}
