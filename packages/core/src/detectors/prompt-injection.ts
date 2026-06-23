import type { Detector } from "./types.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * `prompt_injection_url`. Agent-gated. Detects prompt-control query parameter
 * names and whole path segments that read as instruction overrides. Design
 * rationale and examples live in docs/reason-codes.md.
 */

/**
 * Query parameter names that directly address an LLM control plane. Compared
 * case-insensitively against the exact decoded parameter name.
 */
const PROMPT_CONTROL_PARAMS = new Set([
  "role",
  "system",
  "system_prompt",
  "systemprompt",
  "prompt",
  "instruction",
  "instructions",
  "assistant",
  "developer",
  "jailbreak",
]);

/**
 * Whole-segment instruction-override phrasing after separator normalization.
 */
const OVERRIDE_PHRASE =
  /^(?:ignore|disregard|forget|override)(?: (?:all|the|any))?(?: (?:previous|prior|earlier|above))?(?: (?:instructions?|prompts?|messages?|context|rules?))$/;

/** A standalone "you are now …" / "act as …" persona-reset opener. */
const PERSONA_RESET = /^(?:you are now|act as|pretend (?:to be|you are)|new instructions?)$/;

/**
 * Normalize a single raw path segment to lowercase words. Defensive: returns
 * null if decoding fails.
 */
function normalizeSegment(raw: string, maxDecodeDepth: number): string | null {
  if (raw === "") return null;
  let decoded: string;
  try {
    decoded = boundedDecode(raw.replace(/\+/g, " "), maxDecodeDepth).decoded;
  } catch {
    return null;
  }
  const words = decoded
    .toLowerCase()
    .replace(/[-_+.]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return words === "" ? null : words;
}

export const promptInjection: Detector = {
  id: "prompt_injection_url",
  layer: "lexical",
  agentGated: true,
  run(ctx) {
    // 1. Prompt-control query parameter with a non-empty value.
    if (ctx.query) {
      for (const pair of ctx.query.split("&")) {
        if (pair === "") continue;
        const eq = pair.indexOf("=");
        if (eq === -1) continue;
        const rawKey = pair.slice(0, eq);
        const rawValue = pair.slice(eq + 1);
        if (rawValue === "") continue;

        let key: string;
        try {
          key = boundedDecode(rawKey, ctx.runtime.maxDecodeDepth).decoded.toLowerCase();
        } catch {
          continue;
        }
        if (!PROMPT_CONTROL_PARAMS.has(key)) continue;

        return [
          {
            code: "prompt_injection_url",
            detail:
              `query parameter '${key}' addresses an LLM control channel ` +
              `(role/system/prompt) — a prompt-injection payload in the URL`,
          },
        ];
      }
    }

    // 2. Instruction-override path segment.
    if (ctx.path) {
      for (const rawSeg of ctx.path.split("/")) {
        const seg = normalizeSegment(rawSeg, ctx.runtime.maxDecodeDepth);
        if (seg === null) continue;
        if (OVERRIDE_PHRASE.test(seg) || PERSONA_RESET.test(seg)) {
          return [
            {
              code: "prompt_injection_url",
              detail:
                `path segment '${seg}' reads as an instruction override ` +
                `(ignore/disregard previous instructions) — a prompt-injection payload in the URL`,
            },
          ];
        }
      }
    }

    return [];
  },
};
