import type { InspectionContext } from "../detectors/types.js";
import { buildInspectionContext, buildParsedUrl } from "./context.js";
import { deriveHostFacts } from "./host-facts.js";
import { prepare } from "./prepare.js";
import { parseRawParts } from "./raw-parts.js";
import type { RawUrlTokens } from "./raw-tokens.js";
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

  return parsePrepared(input, prepared, runtime);
}

/**
 * Internal parse entrypoint for callers that already prepared and tokenized an
 * input. This keeps the public parse() contract unchanged while allowing
 * inspect() to share its raw tokenization with structural scans.
 */
export function parsePrepared(
  input: string,
  prepared: string,
  runtime: RuntimeConfig,
  tokens?: RawUrlTokens,
): InspectionContext | null {
  const raw = parseRawParts(prepared, tokens);
  if (raw === null) return null;

  const facts = deriveHostFacts(raw.rawHost);
  const parsed = buildParsedUrl(raw, facts);
  return buildInspectionContext(input, raw, facts, parsed, runtime);
}
