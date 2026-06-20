#!/usr/bin/env node
import { inspect, type InspectResult } from "linklint";
import { parseCli, UsageError } from "./args.js";
import { renderJson, renderResults } from "./render.js";
import { resolveExitCode } from "./policy.js";

/** Package version, kept in sync with package.json. */
export const CLI_VERSION = "0.1.0-dev.0";

/** Usage text printed by `--help`. */
export const USAGE = `linklint — offline URL deception check

Usage:
  linklint check <url...>          inspect one or more URLs
  linklint check --json <url...>   emit a JSON array of full InspectResult objects

Flags:
  --json                emit machine-readable JSON (no human text)
  --fail-on <severity>  exit non-zero at/above this severity (default: high)
                        valid: info|low|medium|high|critical
  --allow-invalid       treat unparseable URLs as a pass (default: fail)
  --quiet               one line per URL
  --no-color            disable ANSI color
  --offline             reserved no-op in v1 (accepted and ignored)
  --help                print this help and exit
  --version             print version and exit

Exit codes:
  0  all URLs below the --fail-on threshold and none invalid (or allowed)
  1  any URL at/above the threshold, or any invalid URL (unless --allow-invalid)
  2  usage error`;

/**
 * Run the CLI over a raw argv tail (everything after `node script`). Pure of
 * process-level side effects beyond writing to the given streams; returns the
 * intended exit code so it can be unit-tested without spawning a process.
 */
export function run(
  argv: readonly string[],
  out: (line: string) => void = (s) => process.stdout.write(`${s}\n`),
  err: (line: string) => void = (s) => process.stderr.write(`${s}\n`),
): 0 | 1 | 2 {
  let cli;
  try {
    cli = parseCli(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      err(`error: ${e.message}`);
      err("");
      err(USAGE);
      return 2;
    }
    throw e;
  }

  if (cli.kind === "help") {
    out(USAGE);
    return 0;
  }
  if (cli.kind === "version") {
    out(CLI_VERSION);
    return 0;
  }

  const results: InspectResult[] = cli.urls.map((url) => inspect(url));

  if (cli.options.json) {
    out(renderJson(results));
  } else {
    out(
      renderResults(results, {
        quiet: cli.options.quiet,
        noColor: cli.options.noColor,
      }),
    );
  }

  return resolveExitCode(results, {
    failOn: cli.options.failOn,
    allowInvalid: cli.options.allowInvalid,
  });
}

/** Entry point: parse `process.argv`, dispatch, and set `process.exitCode`. */
export function main(): void {
  process.exitCode = run(process.argv.slice(2));
}

// Run when invoked directly (bin entrypoint).
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
