import type { Reason, Severity } from "../schema/types.js";
import { severityForScore } from "./weights.js";

export interface ScoreResult {
  score: number;
  severity: Severity;
}

/**
 * Aggregate scoring reasons with probabilistic OR (FR-SCORE-1a):
 *
 *   score = 1 − Π(1 − wᵢ)
 *
 * Order-independent, saturates toward 1 as signals stack, and never exceeds 1
 * so weights compose without a manual clamp. Informational reasons (weight 0)
 * contribute nothing.
 *
 * The product is rounded to 10 decimal places before it becomes `score`. Weights
 * are two-decimal constants, so every genuine value is far coarser than 1e-10 and
 * is untouched; what the rounding removes is accumulated floating-point error,
 * which would otherwise reach the public field and the JSON output verbatim —
 * `brand_homoglyph` (0.8) + `ascii_homoglyph` (0.2) computes to
 * `0.8400000000000001`, not `0.84`. It also keeps that error off the severity
 * band edges, where an ULP above 0.8 would read `critical` for a score whose
 * exact value is 0.8 (`high`).
 */
export function aggregate(reasons: Reason[]): ScoreResult {
  let inverse = 1;
  for (const reason of reasons) {
    const w = reason.weight;
    if (w <= 0) continue;
    inverse *= 1 - w;
  }
  const score = Number((1 - inverse).toFixed(10));
  return { score, severity: severityForScore(score) };
}
