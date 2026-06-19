import {
  SCHEMA_VERSION,
  type Confusable,
  type InspectResult,
  type Reason,
} from "./types.js";
import { reasonMeta, weightFor, type ReasonCode } from "./reason-codes.js";
import type { InspectionContext } from "../detectors/types.js";
import { aggregate } from "../scoring/score.js";
import { DATA_VERSIONS } from "../data/versions.js";

/** A finding collected during detector execution, before final serialization. */
export interface CollectedFinding {
  code: ReasonCode;
  detail: string;
  confusables?: Confusable[];
}

/**
 * Build a `status: "invalid"` result for unparseable input (FR-IN-4).
 *
 * Invalid stays "not benign" (`score: null`, fail-closed), but it can now carry
 * reasons: a structurally-ambiguous-yet-unresolvable URL (Epic J `ambiguous_
 * authority`) returns `invalid` *with* an explanation instead of a bare
 * `parse_error`. When `findings` is empty we fall back to `parse_error`.
 */
export function buildInvalidResult(
  input: string,
  findings: CollectedFinding[] = [],
): InspectResult {
  const hasFindings = findings.length > 0;
  const reasons: Reason[] = hasFindings
    ? findings
        .map((f) => ({
          code: f.code,
          layer: reasonMeta(f.code).layer,
          detail: f.detail,
          weight: weightFor(f.code),
        }))
        .sort((a, b) => b.weight - a.weight || a.code.localeCompare(b.code))
    : [
        {
          code: "parse_error",
          layer: "lexical",
          detail: "input is not a parseable URL or hostname",
          weight: 0,
        },
      ];

  return {
    schemaVersion: SCHEMA_VERSION,
    status: "invalid",
    input,
    parsed: null,
    score: null,
    severity: null,
    reasons,
    confusables: hasFindings ? findings.flatMap((f) => f.confusables ?? []) : [],
    checksRun: hasFindings ? ["lexical"] : [],
    checksSkipped: hasFindings
      ? ["resolution", "reputation"]
      : ["lexical", "resolution", "reputation"],
    dataVersions: DATA_VERSIONS,
  };
}

/**
 * Build a `status: "ok"` result from a parsed context and the collected
 * findings. Attaches weights from the registry, aggregates the score, orders
 * reasons (weight desc, then code), and assembles the confusables expansion.
 */
export function buildOkResult(
  ctx: InspectionContext,
  findings: CollectedFinding[],
  skippedDetectors: string[],
): InspectResult {
  const reasons: Reason[] = findings.map((f) => ({
    code: f.code,
    layer: reasonMeta(f.code).layer,
    detail: f.detail,
    weight: weightFor(f.code),
  }));

  reasons.sort((a, b) => (b.weight - a.weight) || a.code.localeCompare(b.code));

  const confusables: Confusable[] = findings.flatMap((f) => f.confusables ?? []);

  const { score, severity } = aggregate(reasons);

  const checksSkipped = [...skippedDetectors, "resolution", "reputation"];

  return {
    schemaVersion: SCHEMA_VERSION,
    status: "ok",
    input: ctx.input,
    parsed: ctx.parsed,
    score,
    severity,
    reasons,
    confusables,
    checksRun: ["lexical"],
    checksSkipped,
    dataVersions: DATA_VERSIONS,
  };
}
