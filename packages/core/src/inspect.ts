import type { InspectOptions, InspectResult } from "./schema/types.js";
import { parse } from "./parse/parse.js";
import { DETECTORS } from "./detectors/registry.js";
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
  let ctx;
  try {
    ctx = parse(input);
  } catch {
    // Parsing must be total — any unexpected failure is treated as invalid input.
    return buildInvalidResult(input);
  }
  if (ctx === null) return buildInvalidResult(input);

  const findings: CollectedFinding[] = [];
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
