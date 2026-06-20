/**
 * Output renderers for the linklint CLI. Pure string producers — they take
 * inspection results and options and return text, with no process side effects,
 * so they are unit-testable without spawning a process.
 */
import type { InspectResult, Severity } from "linklint";

/** Renderer options that affect formatting. */
export interface RenderOptions {
  /** Minimal one-line-per-URL output. */
  quiet: boolean;
  /** Disable ANSI color escapes. */
  noColor: boolean;
}

/** ANSI SGR codes per severity (used only when color is enabled). */
const SEVERITY_COLOR: Record<Severity, string> = {
  info: "32", // green
  low: "32", // green
  medium: "33", // yellow
  high: "31", // red
  critical: "35", // magenta
};

const RESET = "\u001b[0m";

/** Wrap `text` in an ANSI color when color is enabled; otherwise return as-is. */
function colorize(text: string, code: string, noColor: boolean): string {
  if (noColor) return text;
  return `\u001b[${code}m${text}${RESET}`;
}

/** A short uppercase badge for a result's severity (or INVALID). */
function badge(result: InspectResult, noColor: boolean): string {
  if (result.status === "invalid" || result.severity === null) {
    return colorize("INVALID", "31", noColor);
  }
  const label = result.severity.toUpperCase();
  return colorize(label, SEVERITY_COLOR[result.severity], noColor);
}

/** Format the score in [0,1] as a fixed-width string, or `n/a`. */
function formatScore(score: number | null): string {
  return score === null ? "n/a" : score.toFixed(2);
}

/** One terse line for a single result (used by `--quiet`). */
function renderQuiet(result: InspectResult, noColor: boolean): string {
  return `${badge(result, noColor)}\t${formatScore(result.score)}\t${result.input}`;
}

/** The detailed, human-readable block for a single result. */
function renderHuman(result: InspectResult, noColor: boolean): string {
  const lines: string[] = [];
  lines.push(`${badge(result, noColor)}  ${formatScore(result.score)}  ${result.input}`);

  if (result.status === "invalid") {
    lines.push("  not a parseable URL — not checked (do not assume safe)");
    return lines.join("\n");
  }

  const parsed = result.parsed;
  if (parsed !== null) {
    if (parsed.effectiveHost !== null) {
      lines.push(`  host:   ${parsed.effectiveHost}`);
    }
    if (parsed.registrableDomain !== null) {
      lines.push(`  domain: ${parsed.registrableDomain}`);
    }
  }

  if (result.reasons.length > 0) {
    lines.push("  reasons:");
    for (const reason of result.reasons) {
      const weight = reason.weight.toFixed(2);
      lines.push(`    - ${reason.code} (+${weight})  ${reason.detail}`);
    }
  } else {
    lines.push("  reasons: none");
  }

  if (result.confusables.length > 0) {
    lines.push("  confusables:");
    for (const c of result.confusables) {
      lines.push(
        `    - ${c.char} ${c.codepoint} ~ ${c.confusableWith} (${c.component} @${c.position})`,
      );
    }
  }

  return lines.join("\n");
}

/**
 * Render a batch of results to a single string for the default (human) and
 * `--quiet` modes. Blocks are separated by a blank line in full mode.
 */
export function renderResults(
  results: readonly InspectResult[],
  options: RenderOptions,
): string {
  if (options.quiet) {
    return results.map((r) => renderQuiet(r, options.noColor)).join("\n");
  }
  return results.map((r) => renderHuman(r, options.noColor)).join("\n\n");
}

/** Render a batch of results as a pretty-printed JSON array (`--json`). */
export function renderJson(results: readonly InspectResult[]): string {
  return JSON.stringify(results, null, 2);
}
