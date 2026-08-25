import {
  SCHEMA_VERSION,
  type Confusable,
  type InspectResult,
  type Reason,
} from "./types.js";
import { compareReasons, reasonMeta, weightFor, type ReasonCode } from "./reason-codes.js";
import type { InspectionContext } from "../detectors/types.js";
import { aggregate } from "../scoring/score.js";
import { applySuppressions, suppressionHostContext } from "../scoring/suppress.js";
import { DATA_VERSIONS } from "../data/versions.js";
import { currentPslSnapshot } from "../data/psl-provenance.js";

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
 * reasons: a structurally-ambiguous-yet-unresolvable URL (`ambiguous_
 * authority`) returns `invalid` *with* an explanation instead of a bare
 * `parse_error`. When `findings` is empty we fall back to `parse_error`.
 *
 * `optionSkipped` carries the option-intake tokens (LINK-sjsxfqoo). They lead
 * `checksSkipped` because reading the caller's options precedes every check —
 * and they must reach this path too: an input that fails to parse must still
 * report the configuration the caller lost. Defaults to empty, so the invalid
 * result for a well-formed call is byte-for-byte unchanged.
 */
export function buildInvalidResult(
  input: string,
  findings: CollectedFinding[] = [],
  parseErrorDetail?: string,
  optionSkipped: readonly string[] = [],
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
        .sort(compareReasons)
    : [
        {
          code: "parse_error",
          layer: "lexical",
          // `parseErrorDetail` sharpens the message for a caller-contract failure
          // (non-string input) without minting a reason code — the registry and
          // its documented count stay untouched. Omitted everywhere else, so
          // existing output is byte-identical.
          detail: parseErrorDetail ?? "input is not a parseable URL or hostname",
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
    // Deterministic lexical verdict: fully confident (FR-SCORE-2b). Probabilistic
    // enrichers only ever lower this in inspectAsync.
    confidence: 1,
    reasons,
    confusables: hasFindings ? findings.flatMap((f) => f.confusables ?? []) : [],
    checksRun: hasFindings ? ["lexical"] : [],
    checksSkipped: [
      ...optionSkipped,
      ...(hasFindings
        ? ["resolution", "reputation"]
        : ["lexical", "resolution", "reputation"]),
    ],
    dataVersions: DATA_VERSIONS,
    // PSL-snapshot provenance + advisory staleness of the trust boundary this
    // verdict rests on (schema 1.2, LINK-rkhuihjx).
    pslSnapshot: currentPslSnapshot(),
  };
}

/**
 * Build a `status: "ok"` result from a parsed context and the collected
 * findings. Attaches weights from the registry, aggregates the score, orders
 * reasons (weight desc, then code), and assembles the confusables expansion.
 *
 * `policyFindings` is the separate policy channel (layer `policy`, weight 0):
 * its reasons go through the same map and sort but contribute nothing to the
 * score. `policyRan` records whether the policy channel actually produced a
 * verdict — configured AND at least one axis completed (LINK-ymprmvhr) — and
 * gates the `policy` entry in `checksRun` so that, with no policy configured,
 * `checksRun` stays exactly `["lexical"]`. A partially failed channel still
 * counts as run; its failed axes appear separately as `policy:<axis id>` in
 * `checksSkipped`, so the two lists never disagree about the same token.
 *
 * `agentRan` is the parallel flag for the agent channel: when `InspectOptions.
 * agentMode` is on AND ≥1 agent-gated check was evaluated, the `agent` channel
 * token is appended to `checksRun`. The deterministic channel order when all
 * three run is `["lexical", "policy", "agent"]`. Like `policyRan`, agent-gated
 * checks disabled by `agentMode: false` are NOT recorded in `checksSkipped`, so
 * the default path stays byte-identical.
 *
 * `suppressRan` is the caller false-positive escape hatch flag: when
 * `InspectOptions.suppressReasons` is present, matched reasons are annotated
 * `suppressed` (weight zeroed, so `aggregate` drops them) and the `suppression`
 * token is appended to `checksRun` — honest that a caller escape hatch applied.
 * Absent the option, suppression is inert and the output is byte-for-byte
 * unchanged.
 */
export function buildOkResult(
  ctx: InspectionContext,
  findings: CollectedFinding[],
  skippedDetectors: string[],
  policyFindings: CollectedFinding[] = [],
  policyRan = false,
  agentRan = false,
  suppressRan = false,
): InspectResult {
  const built: Reason[] = [...findings, ...policyFindings].map((f) => ({
    code: f.code,
    layer: reasonMeta(f.code).layer,
    detail: f.detail,
    weight: weightFor(f.code),
  }));

  // Caller false-positive escape hatch: annotate matched reasons `suppressed`
  // and zero their weight BEFORE sort/aggregate, so the score drops as if the
  // signal were absent while the reason stays visible. Inert (same array) when no
  // suppression rule is configured — keeps the default path byte-for-byte.
  const reasons: Reason[] = applySuppressions(
    built,
    ctx.runtime.suppressReasons,
    suppressionHostContext(ctx.registrableDomain),
  );

  reasons.sort(compareReasons);

  const confusables: Confusable[] = findings.flatMap((f) => f.confusables ?? []);

  const { score, severity } = aggregate(reasons);

  const checksSkipped = [...skippedDetectors, "resolution", "reputation"];

  // Channel tokens in deterministic order: lexical always; policy when the
  // policy channel ran; agent when the agent-gated channel ran; suppression when
  // the caller escape hatch was configured. Appended in this fixed order so the
  // default path is exactly ["lexical"].
  const checksRun = ["lexical"];
  if (policyRan) checksRun.push("policy");
  if (agentRan) checksRun.push("agent");
  if (suppressRan) checksRun.push("suppression");

  return {
    schemaVersion: SCHEMA_VERSION,
    status: "ok",
    input: ctx.input,
    parsed: ctx.parsed,
    score,
    severity,
    // Deterministic lexical verdict: fully confident (FR-SCORE-2b). Probabilistic
    // enrichers only ever lower this in inspectAsync.
    confidence: 1,
    reasons,
    confusables,
    checksRun,
    checksSkipped,
    dataVersions: DATA_VERSIONS,
    // PSL-snapshot provenance + advisory staleness of the trust boundary this
    // verdict rests on (schema 1.2, LINK-rkhuihjx).
    pslSnapshot: currentPslSnapshot(),
  };
}
