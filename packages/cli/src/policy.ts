/**
 * Exit-code policy for the linklint CLI. Pure functions over inspection results
 * and resolved options — no process side effects, so they are unit-testable
 * without spawning a process.
 */
import type { InspectResult, Severity } from "linklint";

/** Severity bands in ascending order of concern. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;

/** The set of valid `--fail-on` severity values. */
export const VALID_FAIL_ON: ReadonlySet<string> = new Set(SEVERITY_ORDER);

/** Rank a severity by its position in {@link SEVERITY_ORDER}. */
export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/** Type guard: is `value` a valid severity / `--fail-on` value? */
export function isSeverity(value: string): value is Severity {
  return VALID_FAIL_ON.has(value);
}

/** Inputs the exit policy needs from the resolved CLI options. */
export interface ExitPolicyOptions {
  /** Severity threshold at or above which a result fails the run. */
  failOn: Severity;
  /** When true, invalid (unparseable) URLs do not fail the run. */
  allowInvalid: boolean;
}

/**
 * Resolve the process exit code for a batch of inspection results.
 *
 * - `0` — all results below the `failOn` threshold and none invalid (or invalid
 *   allowed).
 * - `1` — any result at/above the threshold, OR any invalid result (unless
 *   `allowInvalid`). Fail-closed: an invalid URL is never assumed safe.
 *
 * Usage errors (exit `2`) are handled at the dispatch layer, not here.
 */
export function resolveExitCode(
  results: readonly InspectResult[],
  options: ExitPolicyOptions,
): 0 | 1 {
  const threshold = severityRank(options.failOn);
  for (const result of results) {
    if (result.status === "invalid") {
      if (!options.allowInvalid) return 1;
      continue;
    }
    if (result.severity !== null && severityRank(result.severity) >= threshold) {
      return 1;
    }
  }
  return 0;
}
