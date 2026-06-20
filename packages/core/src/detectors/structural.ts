import type { DetectorFinding } from "./types.js";
import type { RuntimeConfig } from "../parse/runtime.js";
import { scanAmbiguousAuthority } from "./ambiguous-authority.js";
import { scanSeparatorLookalike } from "./separator-lookalike.js";
import { scanIdnaMappingAmbiguity } from "./idna-mapping-ambiguity.js";
import { scanControlChar } from "./control-char.js";

/**
 * Shared context handed to every structural scan. Built once per `inspect()`
 * call so scans don't each re-derive the prepared form or runtime knobs.
 */
export interface ScanContext {
  input: string;
  prepared: string;
  runtime: RuntimeConfig;
}

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
 * Ordered list of structural scans run by `inspect()` ahead of parse(). Same
 * order as the previous inline array (ambiguous-authority, separator-lookalike,
 * idna-mapping-ambiguity, control-char). scanControlChar is the only scan that
 * decodes, so only it takes `runtime` (the depth knob); the others are pure
 * string scans.
 */
export const STRUCTURAL_SCANS: StructuralScan[] = [
  { id: "ambiguous_authority", run: (ctx) => scanAmbiguousAuthority(ctx.prepared) },
  { id: "separator_lookalike", run: (ctx) => scanSeparatorLookalike(ctx.prepared) },
  { id: "idna_mapping_ambiguity", run: (ctx) => scanIdnaMappingAmbiguity(ctx.prepared) },
  { id: "control_char", run: (ctx) => scanControlChar(ctx.prepared, ctx.runtime) },
];
