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
import { authorityRegion } from "./parse/authority-region.js";

/**
 * Inspect a single URL or bare hostname. Synchronous, zero-network, never throws
 * (FR-LIB-2, FR-IN-4, NFR-PERF-1). Returns the stable versioned schema for every
 * input — `status: "ok"` for anything parseable, `status: "invalid"` otherwise.
 */
export function inspect(input: string, options: InspectOptions = {}): InspectResult {
  // Structural scans over the raw input. They run independently of
  // parse() so they can flag the very inputs parse() discards (backslash, empty
  // authority, multi-colon host, delimiter look-alikes, encoded control chars)
  // instead of losing the signal to `invalid`.
  const runtime = normalizeOptions(options);
  const structural: CollectedFinding[] = [];
  // Structural scans run before parse, so this skip list must exist ahead of the
  // parse branch and feed both result paths. A failed scan is recorded with the
  // same `lexical:<id>` shape the parsed-detector loop uses below (FR-D-13).
  const structuralSkipped: string[] = [];
  const prepared = prepare(input);
  // Every structural scan needs the authority region — compute it once and share.
  const scanCtx = { input, prepared, runtime, authority: authorityRegion(prepared) };
  for (const scan of STRUCTURAL_SCANS) {
    try {
      structural.push(...scan.run(scanCtx));
    } catch {
      // A scan must never abort inspection (FR-D-13). Record the skip so the
      // score is reported as a lower bound rather than silently swallowing it.
      structuralSkipped.push(`lexical:${scan.id}`);
    }
  }

  let ctx;
  try {
    ctx = parse(input, runtime);
  } catch {
    // Parsing must be total — any unexpected failure is treated as invalid input.
    // The invalid path's bare `"lexical"` checksSkipped entry already states that
    // the entire lexical layer (structural scans included) was not fully applied,
    // so per-scan `lexical:<id>` skips are deliberately not threaded here — doing
    // so would change the cucumber-pinned invalid CSV value. (LINK-hastsuzd)
    return buildInvalidResult(input, structural);
  }
  // Unparseable input: still explain itself if the authority was ambiguous.
  if (ctx === null) return buildInvalidResult(input, structural);

  const findings: CollectedFinding[] = [...structural];
  // Seed with any structural-scan skips so they reach checksSkipped on the OK path.
  const skippedDetectors: string[] = [...structuralSkipped];

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
