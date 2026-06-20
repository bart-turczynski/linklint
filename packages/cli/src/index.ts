/**
 * @linklint/cli — a thin, offline command-line interface over the linklint core.
 *
 * Exports the testable surface (arg parsing, renderers, exit-policy resolver,
 * and the top-level `run`) so the pieces can be unit-tested without spawning a
 * process.
 */
export { run, main, USAGE, CLI_VERSION } from "./cli.js";
export {
  parseCli,
  UsageError,
  type ParsedCli,
  type CheckOptions,
} from "./args.js";
export { parseUrlLines } from "./lines.js";
export {
  renderResults,
  renderJson,
  type RenderOptions,
} from "./render.js";
export {
  resolveExitCode,
  severityRank,
  isSeverity,
  SEVERITY_ORDER,
  VALID_FAIL_ON,
  type ExitPolicyOptions,
} from "./policy.js";
