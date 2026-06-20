import type { InspectOptions, InspectResult } from "./schema/types.js";
import { parse } from "./parse/parse.js";
import { prepare } from "./parse/prepare.js";
import { DETECTORS } from "./detectors/registry.js";
import { STRUCTURAL_SCANS } from "./detectors/structural.js";
import {
  buildInvalidResult,
  buildOkResult,
  type CollectedFinding,
} from "./schema/serialize.js";
import { policyConfigured, runPolicy } from "./policy/policy.js";
import { normalizeOptions } from "./parse/runtime.js";

/**
 * Inspect a single URL or bare hostname. Synchronous, zero-network, never throws
 * (FR-LIB-2, FR-IN-4, NFR-PERF-1). Returns the stable versioned schema for every
 * input — `status: "ok"` for anything parseable, `status: "invalid"` otherwise.
 */
export function inspect(input: string, options: InspectOptions = {}): InspectResult {
  // J1/J2/J3/J9 — structural scans over the raw input. They run independently of
  // parse() so they can flag the very inputs parse() discards (backslash, empty
  // authority, multi-colon host, delimiter look-alikes, encoded control chars)
  // instead of losing the signal to `invalid`.
  const runtime = normalizeOptions(options);
  const structural: CollectedFinding[] = [];
  const prepared = prepare(input);
  const scanCtx = { input, prepared, runtime };
  for (const scan of STRUCTURAL_SCANS) {
    try {
      structural.push(...scan.run(scanCtx));
    } catch {
      // A scan must never abort inspection (FR-D-13).
    }
  }

  let ctx;
  try {
    ctx = parse(input, runtime);
  } catch {
    // Parsing must be total — any unexpected failure is treated as invalid input.
    return buildInvalidResult(input, structural);
  }
  // Unparseable input: still explain itself if the authority was ambiguous.
  if (ctx === null) return buildInvalidResult(input, structural);

  const findings: CollectedFinding[] = [...structural];
  const skippedDetectors: string[] = [];

  for (const detector of DETECTORS) {
    try {
      for (const f of detector.run(ctx)) {
        findings.push({ code: f.code, detail: f.detail, ...(f.confusables ? { confusables: f.confusables } : {}) });
      }
    } catch {
      // A detector-local failure must not abort inspection (FR-D-13). The score
      // becomes a lower bound and the detector is recorded as skipped.
      skippedDetectors.push(`lexical:${detector.id}`);
    }
  }

  // Policy channel (FR-POLICY-*): a separate, caller-configured set of axes that
  // annotate without scoring (layer "policy", weight 0). It runs only when the
  // caller configured a policy field — otherwise the result is byte-identical to
  // today (no `policy` in checksRun, no policy reasons).
  const policyRan = policyConfigured(options);
  let policyFindings: CollectedFinding[] = [];
  if (policyRan) {
    try {
      policyFindings = runPolicy(ctx, options);
    } catch {
      // A policy failure must never abort inspection (FR-D-13).
      skippedDetectors.push("policy");
    }
  }

  return buildOkResult(ctx, findings, skippedDetectors, policyFindings, policyRan);
}
