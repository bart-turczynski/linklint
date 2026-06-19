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
 */
export function aggregate(reasons: Reason[]): ScoreResult {
  let inverse = 1;
  for (const reason of reasons) {
    const w = reason.weight;
    if (w <= 0) continue;
    inverse *= 1 - w;
  }
  const score = 1 - inverse;
  return { score, severity: severityForScore(score) };
}
