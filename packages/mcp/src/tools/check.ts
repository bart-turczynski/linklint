import { inspect, type InspectResult } from "linklint";
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
  "Returns a structured verdict: `severity` (info|low|medium|high|critical), a " +
  "`score` in [0,1], and named `reasons`. Treat `high`/`critical` as do-not-fetch; " +
  "treat `status: \"invalid\"` as not-checked (do NOT assume it is safe). Use this " +
  "to defend against prompt-injection links.";

export const CHECK_URL_INPUT = {
  url: z.string().describe("The URL or bare hostname to inspect (untrusted input is fine)."),
} as const;

export const CHECK_DOMAIN_INPUT = {
  domain: z.string().describe("The domain / hostname (or URL) to inspect."),
} as const;

/**
 * The single point of truth: delegate to the core. The adapter never
 * reimplements or forks detector/scoring logic (channel rule, architecture §7.2).
 */
export function runCheck(input: string): InspectResult {
  return inspect(input);
}

/** Shape a core result into an MCP tool result (text JSON + structured content). */
export function toToolResult(result: InspectResult) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
    structuredContent: result as unknown as Record<string, unknown>,
  };
}
