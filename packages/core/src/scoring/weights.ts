import type { Severity } from "../schema/types.js";
import { REASON_CODES, type ReasonCode } from "../schema/reason-codes.js";

/**
 * Version pin for the scoring weights + severity bands. Surfaced in
 * `dataVersions.weights` so any verdict is reproducible. Bump deliberately
 * whenever a weight or band changes (NFR-DATA-1).
 */
export const WEIGHTS_VERSION = "1.1";

/**
 * Severity bands (FR-SCORE-1b):
 *   info     = 0
 *   low      = (0, 0.25]
 *   medium   = (0.25, 0.5]
 *   high     = (0.5, 0.8]
 *   critical = (0.8, 1]
 */
export function severityForScore(score: number): Severity {
  if (score <= 0) return "info";
  if (score <= 0.25) return "low";
  if (score <= 0.5) return "medium";
  if (score <= 0.8) return "high";
  return "critical";
}

/**
 * Transparent, version-pinned weights map keyed by reason code, derived from the
 * registry. Exported for docs/UI surfaces that want the table directly.
 */
export const WEIGHTS: Readonly<Record<ReasonCode, number>> = Object.fromEntries(
  (Object.keys(REASON_CODES) as ReasonCode[]).map((code) => [code, REASON_CODES[code].weight]),
) as Record<ReasonCode, number>;
