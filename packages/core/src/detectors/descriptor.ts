import type { Layer } from "../schema/types.js";
import type { ReasonCode } from "../schema/reason-codes.js";
import type { RuntimeConfig } from "../parse/runtime.js";
import type { AuthorityRegion } from "../parse/authority-region.js";
import type { DetectorFinding, InspectionContext } from "./types.js";

/**
 * Shared context handed to every structural scan. Built once per `inspect()`
 * call so scans don't each re-derive the prepared form, runtime knobs, or the
 * authority region (every scan needs the latter — compute it once).
 *
 * Lives here (rather than in structural.ts) so the descriptor union can
 * reference it without a structural.ts ↔ checks.ts import cycle. structural.ts
 * re-exports it so its public surface is unchanged.
 */
export interface ScanContext {
  input: string;
  prepared: string;
  runtime: RuntimeConfig;
  authority: AuthorityRegion;
}

/**
 * Fields shared by every check descriptor — the single source of truth for a
 * check's identity and the reason codes it can emit. Weights and summaries are
 * still owned by `schema/reason-codes.ts`; this registry owns only the
 * code→check wiring and run thunks.
 */
export interface CheckDescriptorBase {
  id: string;
  layer: Layer;
  emits: readonly ReasonCode[];
  /** Whether a runtime failure of this check is recorded in `checksSkipped`. */
  skipReportable: boolean;
}

/** A structural scan: runs over the prepared/raw input ahead of parse(). */
export interface StructuralCheckDescriptor extends CheckDescriptorBase {
  phase: "structural";
  run(ctx: ScanContext): DetectorFinding[];
}

/** A parsed detector: runs over the fully parsed `InspectionContext`. */
export interface ParsedCheckDescriptor extends CheckDescriptorBase {
  phase: "parsed";
  run(ctx: InspectionContext): DetectorFinding[];
}

/** The unified descriptor for all 29 checks. */
export type CheckDescriptor = StructuralCheckDescriptor | ParsedCheckDescriptor;
