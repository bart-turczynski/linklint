#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { inspect, type InspectResult } from "linklint";
import { parseCli, UsageError, type CheckOptions } from "./args.js";
import { parseUrlLines } from "./lines.js";
import { renderJson, renderResults } from "./render.js";
import { resolveExitCode } from "./policy.js";

/** Package version, kept in sync with package.json. */
export const CLI_VERSION = "0.1.0-dev.0";

/** Usage text printed by `--help`. */
export const USAGE = `linklint — offline URL deception check

Usage:
  linklint check <url...>          inspect one or more URLs
  linklint check                   read URLs from stdin (one per line) when piped
  linklint check --json <url...>   emit a JSON array of full InspectResult objects
  linklint batch <file>            inspect URLs from a file (one per line)

Files and stdin skip blank lines and lines starting with '#'.

Flags:
  --json                emit machine-readable JSON (no human text)
  --fail-on <severity>  exit non-zero at/above this severity (default: high)
                        valid: info|low|medium|high|critical
  --allow-invalid       treat unparseable URLs as a pass (default: fail)
  --quiet               one line per URL
  --no-color            disable ANSI color
  --agent               enable agent-mode detectors (e.g. prompt-injection via URL)
  --allow-idn           permit internationalized (Unicode/punycode) domains
                        (default: IDNs are blocked at 'high')
  --idn-allow <domain>  exempt a registrable domain from the IDN block (repeatable)
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

  let urls: string[];
  if (cli.kind === "batch") {
    let text: string;
    try {
      text = readFileSync(cli.file, "utf8");
    } catch (e) {
      err(`error: cannot read file: ${cli.file}`);
      err(`  ${e instanceof Error ? e.message : String(e)}`);
      err("");
      err(USAGE);
      return 2;
    }
    urls = parseUrlLines(text);
  } else if (cli.stdin) {
    // `check` with no URLs (or `-`): read stdin only when piped.
    if (process.stdin.isTTY) {
      err("error: no URLs given to check");
      err("");
      err(USAGE);
      return 2;
    }
    let text: string;
    try {
      text = readFileSync(0, "utf8");
    } catch (e) {
      err(`error: cannot read stdin`);
      err(`  ${e instanceof Error ? e.message : String(e)}`);
      err("");
      err(USAGE);
      return 2;
    }
    urls = parseUrlLines(text);
  } else {
    urls = cli.urls;
  }

  return runInspections(urls, cli.options, out);
}

/**
 * Inspect each URL and emit output. In `--json` mode all results are collected
 * and emitted as one JSON array. Otherwise verdicts are streamed one line (or
 * one block) at a time via `out`, so output appears as the run progresses and a
 * single bad/invalid URL never aborts the run. Returns the aggregate exit code.
 */
function runInspections(
  urls: readonly string[],
  options: CheckOptions,
  out: (line: string) => void,
): 0 | 1 {
  const results: InspectResult[] = [];
  const inspectOptions = {
    ...(options.agent ? { agentMode: true } : {}),
    // IDNs are blocked by default; --allow-idn opts out, --idn-allow exempts hosts.
    ...(options.allowIdn ? { idnPolicy: "allow" as const } : {}),
    ...(options.idnAllowlist.length > 0 ? { idnAllowlist: options.idnAllowlist } : {}),
  };

  if (options.json) {
    for (const url of urls) {
      results.push(inspect(url, inspectOptions));
    }
    out(renderJson(results));
  } else {
    for (const url of urls) {
      const result = inspect(url, inspectOptions);
      results.push(result);
      out(
        renderResults([result], {
          quiet: options.quiet,
          noColor: options.noColor,
        }),
      );
    }
  }

  return resolveExitCode(results, {
    failOn: options.failOn,
    allowInvalid: options.allowInvalid,
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
