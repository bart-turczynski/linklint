/**
 * @linklint/cli — a thin, offline command-line interface over the linklint core.
 *
 * Supported library API: the testable CLI pieces (arg parsing, line parsing,
 * renderers, exit-policy resolver, constants, and the top-level `run`/`main`).
 * The package publishes only this root entry point plus the `linklint` bin; no
 * deep imports are supported.
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
