import type { DetectorFinding } from "./types.js";
import type { ScanContext, StructuralCheckDescriptor } from "./descriptor.js";
import { CHECKS } from "./checks.js";

// `ScanContext` lives in descriptor.ts (so the descriptor union can reference it
// without an import cycle); re-export it here to keep this module's surface
// unchanged for existing importers.
export type { ScanContext } from "./descriptor.js";

/**
 * A structural scan over the raw/prepared input (J1/J2/J3/J9). Mirrors the
 * {@link Detector} shape: a stable `id` plus a `run` that maps a context to
 * findings. The `run` thunks wrap the standalone `scanX` exports — those keep
 * their `(prepared: string)`-first signatures so tests can call them directly.
 */
export interface StructuralScan {
  id: string;
  run(ctx: ScanContext): DetectorFinding[];
}

/**
 * Ordered list of structural scans run by `inspect()` ahead of parse(). DERIVED
 * from the unified {@link CHECKS} registry: the structural-phase descriptors, in
 * registry order (ambiguous-authority, separator-lookalike,
 * idna-mapping-ambiguity, control-char), projected onto the `{id, run}` shape.
 */
export const STRUCTURAL_SCANS: StructuralScan[] = CHECKS.filter(
  (c): c is StructuralCheckDescriptor => c.phase === "structural",
).map((c) => ({ id: c.id, run: c.run }));
