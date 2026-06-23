import type { InspectionContext } from "../detectors/types.js";
import { buildInspectionContext, buildParsedUrl } from "./context.js";
import { deriveHostFacts } from "./host-facts.js";
import { prepare } from "./prepare.js";
import { parseRawParts } from "./raw-parts.js";
import { normalizeOptions, type RuntimeConfig } from "./runtime.js";

/**
 * Parse an arbitrary string into canonical components, preserving raw values for
 * character-level detectors. Returns `null` when no useful URL/host can be
 * identified — the caller turns that into a `status: "invalid"` result (never
 * throws). See FR-IN-1..4 and architecture §4.1.
 *
 * Pipeline: prepare → parseRawParts → deriveHostFacts → buildParsedUrl →
 * buildInspectionContext. Syntax parsing ("what was written") and derived host
 * facts live in separate modules; this function only wires them together.
 */
export function parse(
  input: string,
  runtime: RuntimeConfig = normalizeOptions({}),
): InspectionContext | null {
  const prepared = prepare(input);
  if (prepared === "") return null;

  const raw = parseRawParts(prepared);
  if (raw === null) return null;

  const facts = deriveHostFacts(raw.rawHost);
  const parsed = buildParsedUrl(raw, facts);
  return buildInspectionContext(input, raw, facts, parsed, runtime);
}
