/**
 * Argument parsing for the linklint CLI, factored out of the bin entrypoint so
 * it can be unit-tested without spawning a process.
 *
 * Uses only `node:util` `parseArgs` — no third-party arg parser.
 */
import { parseArgs } from "node:util";
import type { Severity } from "linklint";
import { isSeverity } from "./policy.js";

/** A usage error: surfaced to the caller as exit code 2 with a message. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

/** Resolved options for the `check` subcommand. */
export interface CheckOptions {
  json: boolean;
  /** Reserved no-op in v1: accepted and ignored. */
  offline: boolean;
  failOn: Severity;
  allowInvalid: boolean;
  quiet: boolean;
  /** True when color output is disabled (`--no-color`). */
  noColor: boolean;
}

/** A fully-parsed CLI invocation. */
export type ParsedCli =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "check"; urls: string[]; stdin: boolean; options: CheckOptions }
  | { kind: "batch"; file: string; options: CheckOptions };

/**
 * Parse a raw argv tail (everything after `node script`). Throws
 * {@link UsageError} on any usage problem (unknown flag, bad `--fail-on`,
 * missing batch file). `--help` / `--version` short-circuit any subcommand.
 *
 * Stays synchronous and pure: it never reads stdin or the filesystem. A `check`
 * with no URLs (or the single positional `-`) is parsed with `stdin: true`, and
 * the caller (`run`) resolves the actual input.
 */
export function parseCli(argv: readonly string[]): ParsedCli {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        json: { type: "boolean", default: false },
        offline: { type: "boolean", default: false },
        "fail-on": { type: "string", default: "high" },
        "allow-invalid": { type: "boolean", default: false },
        quiet: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
        help: { type: "boolean", default: false },
        version: { type: "boolean", default: false },
      },
    });
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }

  const { values, positionals } = parsed;

  if (values.help) return { kind: "help" };
  if (values.version) return { kind: "version" };

  const [command, ...rest] = positionals;
  if (command === undefined) {
    throw new UsageError("no command given (expected: check <url...> | batch <file>)");
  }
  if (command !== "check" && command !== "batch") {
    throw new UsageError(`unknown command: ${command} (expected: check | batch)`);
  }

  const failOn = values["fail-on"] ?? "high";
  if (!isSeverity(failOn)) {
    throw new UsageError(
      `invalid --fail-on value: ${failOn} (expected: info|low|medium|high|critical)`,
    );
  }

  const options: CheckOptions = {
    json: values.json,
    offline: values.offline,
    failOn,
    allowInvalid: values["allow-invalid"],
    quiet: values.quiet,
    noColor: values["no-color"],
  };

  if (command === "batch") {
    if (rest.length === 0) {
      throw new UsageError("no file given to batch (expected: batch <file>)");
    }
    if (rest.length > 1) {
      throw new UsageError("batch takes exactly one file argument");
    }
    const file = rest[0];
    if (file === undefined || file === "") {
      throw new UsageError("no file given to batch (expected: batch <file>)");
    }
    return { kind: "batch", file, options };
  }

  // command === "check": with no URLs, or a single `-`, read from stdin.
  const stdin = rest.length === 0 || (rest.length === 1 && rest[0] === "-");
  return { kind: "check", urls: stdin ? [] : rest, stdin, options };
}
