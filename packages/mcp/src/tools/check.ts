import { inspect, type InspectOptions, type InspectResult } from "linklint";
import { z } from "zod";

/**
 * Pre-fetch guidance baked into both tool descriptions (FR-MCP-3). Makes the
 * agent use case explicit: check untrusted URLs BEFORE fetching them.
 */
export const PREFETCH_GUIDANCE =
  "Inspect an untrusted URL for deception (homographs, confusable characters, " +
  "userinfo spoofs, IP obfuscation, embedded domains, bidi/invisible characters, " +
  "dangerous schemes) BEFORE you fetch, open, or follow it. Fully offline and " +
  "deterministic — no network request is made to the URL. " +
  "By default this matches core inspect(url) semantics; set `agentMode: true` " +
  "to enable agent-gated checks such as prompt-injection URLs, API endpoint " +
  "impersonation, credential-harvesting shapes, data-exfiltration parameters, " +
  "and cloud-metadata SSRF escalation. " +
  "Returns a structured verdict: `severity` (info|low|medium|high|critical), a " +
  "`score` in [0,1], and named `reasons`. Treat `high`/`critical` as do-not-fetch; " +
  "treat `status: \"invalid\"` as not-checked (do NOT assume it is safe). Use this " +
  "to defend against deceptive and agent-targeted links.";

export const CHECK_URL_INPUT = {
  url: z.string().describe("The URL or bare hostname to inspect (untrusted input is fine)."),
  agentMode: z
    .boolean()
    .optional()
    .describe(
      "Enable the core agent-gated detector channel for LLM/tool-use contexts. " +
        "Omitted falls back to the server default (LINKLINT_AGENT_MODE, default false); " +
        "an explicit value here overrides it.",
    ),
} as const;

export const CHECK_DOMAIN_INPUT = {
  domain: z.string().describe("The domain / hostname (or URL) to inspect."),
  agentMode: CHECK_URL_INPUT.agentMode,
} as const;

/**
 * The single point of truth: delegate to the core. The adapter never
 * reimplements or forks detector/scoring logic (channel rule, architecture §7.2).
 */
export function runCheck(input: string, options: Pick<InspectOptions, "agentMode"> = {}): InspectResult {
  return options.agentMode === true ? inspect(input, { agentMode: true }) : inspect(input);
}

/**
 * Resolve the effective agent mode for a call. An explicit per-call value
 * (true OR false) always wins; only an omitted value falls back to the
 * server-level default. Keeps the per-call opt-out honored even when the
 * operator defaults the server to agent mode.
 */
export function resolveAgentMode(perCall: boolean | undefined, serverDefault: boolean): boolean {
  return perCall ?? serverDefault;
}

/**
 * Parse the `LINKLINT_AGENT_MODE` server-default env var. Truthy: `1`, `true`,
 * `yes`, `on` (case-insensitive). Anything else — including unset — is false,
 * preserving the byte-identical-to-core default.
 */
export function parseAgentModeEnv(value: string | undefined): boolean {
  if (value === undefined) return false;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

/** Shape a core result into an MCP tool result (text JSON + structured content). */
export function toToolResult(result: InspectResult) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
    structuredContent: result as unknown as Record<string, unknown>,
  };
}
