import type { InspectOptions, InspectResult } from "./schema/types.js";
import { parse } from "./parse/parse.js";
import { prepare } from "./parse/prepare.js";
import { DETECTORS } from "./detectors/registry.js";
import { scanAmbiguousAuthority } from "./detectors/ambiguous-authority.js";
import { scanSeparatorLookalike } from "./detectors/separator-lookalike.js";
import { scanIdnaMappingAmbiguity } from "./detectors/idna-mapping-ambiguity.js";
import {
  buildInvalidResult,
  buildOkResult,
  type CollectedFinding,
} from "./schema/serialize.js";

/**
 * Inspect a single URL or bare hostname. Synchronous, zero-network, never throws
 * (FR-LIB-2, FR-IN-4, NFR-PERF-1). Returns the stable versioned schema for every
 * input — `status: "ok"` for anything parseable, `status: "invalid"` otherwise.
 */
export function inspect(input: string, _options?: InspectOptions): InspectResult {
  // J1/J2 — structural scans over the raw input. They run independently of
  // parse() so they can flag the very inputs parse() discards (backslash, empty
  // authority, multi-colon host, delimiter look-alikes) instead of losing the
  // signal to `invalid`.
  const structural: CollectedFinding[] = [];
  const prepared = prepare(input);
  for (const scan of [scanAmbiguousAuthority, scanSeparatorLookalike, scanIdnaMappingAmbiguity]) {
    try {
      structural.push(...scan(prepared));
    } catch {
      // A scan must never abort inspection (FR-D-13).
    }
  }

  let ctx;
  try {
    ctx = parse(input);
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

  return buildOkResult(ctx, findings, skippedDetectors);
}
