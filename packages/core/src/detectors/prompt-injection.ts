import type { Detector } from "./types.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * `prompt_injection_url`. SCORING, weight 0.5. **AGENT-GATED** — emits only when
 * `InspectOptions.agentMode` is true (wired via `agentGated: true` in
 * checks.ts). This is the highest false-positive surface of any detector, which
 * is precisely WHY it is gated off the default precision-first verdict: the
 * tokens it keys on (`role=`, `system=`, `prompt=`, `/ignore-previous-…`) also
 * appear in legitimate apps. It targets the LLM-agent / tool-use context, where
 * a URL fetched and fed to a model can smuggle instructions.
 *
 * Two payload shapes, both purely lexical (zero network, consistent with every
 * v1 detector):
 *
 *   - **prompt-control query parameter** — a parameter whose NAME is a
 *     prompt/role-control token (`role`, `system`, `prompt`, `system_prompt`,
 *     `assistant`, …) carrying a non-empty value. The classic
 *     `?role=system&prompt=ignore everything` injection vector.
 *   - **instruction-override path segment** — a path segment whose normalized
 *     text reads as an instruction override (`ignore-previous-instructions`,
 *     `disregard all previous`, `you are now …`). Anchored to whole segments so
 *     an unrelated `/ignored/` directory does not trip it.
 *
 * Conservative / anchored by construction: matching is on EXACT decoded query
 * parameter NAMES (a set membership test, never a substring scan) and on
 * WHOLE-SEGMENT instruction phrases (anchored alternation, no unbounded
 * quantifier nesting — no catastrophic backtracking, well within the <5ms
 * budget). A junk/undecodable value just yields no finding; the detector never
 * throws.
 */

/**
 * Query parameter NAMES that directly address an LLM's control plane (role /
 * system / instruction channel). Compared case-insensitively against the EXACT
 * decoded parameter name — never a substring match — to stay conservative.
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
 * Whole-segment instruction-override phrasing. Each alternative is a fixed
 * anchored phrase (separators normalized to a single space before matching), so
 * the regex has no nested quantifiers and cannot backtrack catastrophically.
 * Anchored with `^…$` against a single normalized path segment.
 */
const OVERRIDE_PHRASE =
  /^(?:ignore|disregard|forget|override)(?: (?:all|the|any))?(?: (?:previous|prior|earlier|above))?(?: (?:instructions?|prompts?|messages?|context|rules?))$/;

/** A standalone "you are now …" / "act as …" persona-reset opener. */
const PERSONA_RESET = /^(?:you are now|act as|pretend (?:to be|you are)|new instructions?)$/;

/**
 * Normalize a single raw path segment to lowercase words separated by single
 * spaces: percent-/plus-decode, replace `-`/`_`/`+`/`.` runs with a space, and
 * collapse whitespace. Defensive — returns null if it cannot decode.
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
