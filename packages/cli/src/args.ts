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
  /** True when agent mode is enabled (`--agent`): enables the agent-gated detectors. */
  agent: boolean;
  /** True when `--allow-idn` is set: permits internationalized domains (default blocks them). */
  allowIdn: boolean;
  /** Registrable domains to exempt from the default IDN block (`--idn-allow`, repeatable). */
  idnAllowlist: string[];
  /**
   * TLDs the caller refuses (`--deny-tld`, repeatable). Emits the weight-0
   * `tld_denied` policy reason. This is the caller's judgment channel: linklint
   * ships no curated high-abuse TLD list of its own (LINK-brsntven), so a caller
   * who wants `.tk` to matter says so here.
   */
  denyTlds: string[];
  /** TLDs the caller permits (`--allow-tld`, repeatable). Emits `tld_not_allowlisted` for anything else. */
  allowTlds: string[];
  /**
   * Registrable domains the caller refuses (`--deny-host`, repeatable). Emits
   * the weight-0 `host_denied` policy reason. Matching is at registrable-domain
   * granularity, so listing `bit.ly` also covers `x.bit.ly`.
   */
  denyHosts: string[];
  /** Registrable domains the caller permits (`--allow-host`, repeatable). Emits `host_not_allowlisted` for anything else. */
  allowHosts: string[];
  /** Schemes the caller permits (`--allow-scheme`, repeatable). Emits `scheme_denied` for anything else. */
  allowSchemes: string[];
  /** Schemes the caller refuses (`--deny-scheme`, repeatable). Emits `scheme_denied`. */
  denySchemes: string[];
  /**
   * Explicit ports the caller refuses (`--deny-port`, repeatable). Emits the
   * weight-0 `port_denied` policy reason. Validated at parse time: the library
   * takes a `number[]` and would silently keep any number handed to it, so a
   * value that is not an integer in `0`–`65535` is a usage error here rather
   * than a deny-list entry that can never match.
   */
  denyPorts: number[];
  /** True when `--deny-non-standard-ports` is set: any explicit non-default port emits `port_denied`. */
  denyNonStandardPorts: boolean;
}

/** Highest valid TCP port; the URL grammar admits `0`–`65535` inclusive. */
const MAX_PORT = 65535;

/**
 * Parse one `--deny-port` value into a port number, or throw {@link UsageError}.
 *
 * Deliberately stricter than `Number()`: the core's `normalizePort` keeps any
 * `number` it is given, so a coerced `NaN`, `8080.5` or `-1` would become a
 * deny-list entry that no parsed URL can ever equal — a policy the caller
 * believes is in force and that silently is not. Failing loudly at the boundary
 * is the only place that distinction is still visible.
 */
function parsePort(value: string): number {
  if (!/^\d{1,5}$/.test(value)) {
    throw new UsageError(
      `invalid --deny-port value: ${value} (expected an integer 0-${MAX_PORT})`,
    );
  }
  const port = Number(value);
  if (port > MAX_PORT) {
    throw new UsageError(
      `invalid --deny-port value: ${value} (expected an integer 0-${MAX_PORT})`,
    );
  }
  return port;
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
        agent: { type: "boolean", default: false },
        "allow-idn": { type: "boolean", default: false },
        "idn-allow": { type: "string", multiple: true },
        "deny-tld": { type: "string", multiple: true },
        "allow-tld": { type: "string", multiple: true },
        "deny-host": { type: "string", multiple: true },
        "allow-host": { type: "string", multiple: true },
        "allow-scheme": { type: "string", multiple: true },
        "deny-scheme": { type: "string", multiple: true },
        "deny-port": { type: "string", multiple: true },
        "deny-non-standard-ports": { type: "boolean", default: false },
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
    agent: values.agent,
    allowIdn: values["allow-idn"],
    idnAllowlist: values["idn-allow"] ?? [],
    denyTlds: values["deny-tld"] ?? [],
    allowTlds: values["allow-tld"] ?? [],
    denyHosts: values["deny-host"] ?? [],
    allowHosts: values["allow-host"] ?? [],
    allowSchemes: values["allow-scheme"] ?? [],
    denySchemes: values["deny-scheme"] ?? [],
    denyPorts: (values["deny-port"] ?? []).map(parsePort),
    denyNonStandardPorts: values["deny-non-standard-ports"],
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
