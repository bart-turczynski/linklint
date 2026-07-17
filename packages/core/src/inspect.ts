import type { InspectOptions, InspectResult } from "./schema/types.js";
import { parsePrepared } from "./parse/parse.js";
import { prepare } from "./parse/prepare.js";
import { tokenizeRawUrl } from "./parse/raw-tokens.js";
import { DETECTORS } from "./detectors/registry.js";
import { STRUCTURAL_SCANS } from "./detectors/structural.js";
import {
  buildInvalidResult,
  buildOkResult,
  type CollectedFinding,
} from "./schema/serialize.js";
import { policyConfigured, runPolicy } from "./policy/policy.js";
import { suppressConfigured } from "./scoring/suppress.js";
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
  const rawTokens = tokenizeRawUrl(prepared);
  // Every structural scan needs the authority region — compute it once and share.
  const scanCtx = { input, prepared, runtime, authority: authorityRegion(prepared, rawTokens) };
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
    ctx = prepared === "" ? null : parsePrepared(input, prepared, runtime, rawTokens);
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

  // Agent channel (FR-AGENT-*): agent-gated detectors are an explicit opt-in
  // (InspectOptions.agentMode). When off they are silently not evaluated — NOT
  // listed in checksSkipped (an available-but-disabled feature channel, not a
  // skipped layer). `agentRan` mirrors `policyRan`: it records that ≥1 gated
  // check was actually evaluated, gating the `agent` token in checksRun so the
  // default path stays byte-identical to today.
  const agentMode = options.agentMode === true;
  let agentRan = false;

  for (const detector of DETECTORS) {
    if (detector.agentGated) {
      if (!agentMode) continue;
      agentRan = true;
    }
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
      policyFindings = runPolicy(ctx);
    } catch {
      // A policy failure must never abort inspection (FR-D-13).
      skippedDetectors.push("policy");
    }
  }

  // Caller false-positive escape hatch (FR — architecture §9): a general
  // suppression channel that annotates matched reasons `suppressed` and zeroes
  // their scoring weight. Configured whenever `suppressReasons` is present; when
  // absent the result is byte-identical to today (no `suppression` in checksRun,
  // no `suppressed` markers). The rules themselves ride on `ctx.runtime`.
  const suppressRan = suppressConfigured(options);

  return buildOkResult(
    ctx,
    findings,
    skippedDetectors,
    policyFindings,
    policyRan,
    agentRan,
    suppressRan,
  );
}
