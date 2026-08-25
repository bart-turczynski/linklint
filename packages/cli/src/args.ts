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
 * The trim the CLI applies to a caller-supplied list value before reading it.
 *
 * The core already applies the identical trim at `normalizedList`, the single
 * choke point every scalar list-valued option routes through (LINK-uxkrtcnw,
 * LINK-qajalduf), so a value the CLI passes along AS A STRING inherits it by
 * construction and needs nothing here.
 *
 * `--deny-port` is the one value the CLI CONSUMES before the core can see it.
 * `denyPorts` is `number[]` at the library boundary, so something has to
 * convert, and whatever the converter rejects never reaches the choke point at
 * all. The conversion cannot move into the core either: `normalizeOptions` is
 * contractually total ("Never throws — inspection must be total"), so a core
 * that took port STRINGS could only drop a malformed one silently — which is
 * the dead-deny-list fail-open `parsePort` exists to prevent. So this is not
 * discipline chosen over inheritance; it is the one value inheritance cannot
 * reach (LINK-patktxpv).
 *
 * Stated once and shared by both CLI-side readers — the separator screen and
 * the port parser — because `assertNotJoined` defines its screen as exactly
 * "the padding trimming cannot reach". If the two readers ever disagreed about
 * what padding is, that sentence would quietly stop being true and the screen
 * would gain or lose characters with it.
 */
function trimFlagValue(value: string): string {
  return value.trim();
}

/**
 * Parse one `--deny-port` value into a port number, or throw {@link UsageError}.
 *
 * Deliberately stricter than `Number()`: the core's `normalizePort` keeps any
 * `number` it is given, so a coerced `NaN`, `8080.5` or `-1` would become a
 * deny-list entry that no parsed URL can ever equal — a policy the caller
 * believes is in force and that silently is not. Failing loudly at the boundary
 * is the only place that distinction is still visible.
 *
 * Padding is stripped first, so `--deny-port " 8080 "` is the port `8080` just
 * as `--deny-tld " com"` is the TLD `com`. Before that the digits check ran on
 * the raw argv string and refused the padded value outright — loud, so nobody
 * believed a policy was in force that was not, but inconsistent with the other
 * seven repeatable value flags and with what both the help text and the README
 * promise (LINK-patktxpv).
 *
 * This cannot weaken the separator screen. `trimFlagValue` strips exactly what
 * `\s` matches, so every separator this could reach is padding by definition,
 * and `assertNotJoined` has already refused anything in the middle by the time
 * a value gets here.
 *
 * The error still echoes the RAW value rather than the trimmed one: it is what
 * the caller typed, and it is how `assertNotJoined` renders the value in the
 * sibling error on this same flag, so the two messages agree.
 */
function parsePort(rawValue: string): number {
  const value = trimFlagValue(rawValue);
  if (!/^\d{1,5}$/.test(value)) {
    throw new UsageError(
      `invalid --deny-port value: ${rawValue} (expected an integer 0-${MAX_PORT})`,
    );
  }
  const port = Number(value);
  if (port > MAX_PORT) {
    throw new UsageError(
      `invalid --deny-port value: ${rawValue} (expected an integer 0-${MAX_PORT})`,
    );
  }
  return port;
}

/**
 * How many repetitions the separator advice spells out before eliding the rest.
 * The example is built from the caller's own value, and a config string joined
 * from thirty TLDs should not produce a thirty-clause error message.
 */
const SUGGESTION_LIMIT = 3;

/**
 * The characters refused inside a single policy value, matched one at a time so
 * the error can name the one the caller actually typed.
 *
 * `,` `;` `|` and whitespace — and nothing else. The set is a judgment about two
 * separate questions, and a character has to answer BOTH the same way to be in
 * here (LINK-stuiljry):
 *
 * 1. Can it occur in a value that matches an axis TODAY? If yes, refusing it
 *    breaks live input, and no amount of good intent recovers that. This is what
 *    keeps `+ - . :` out: `svn+ssh` and `view-source` are real schemes in the
 *    RFC 3986 grammar, `.` and `-` are in every host and in punycode TLDs like
 *    `xn--p1ai`, and a leading or trailing `:` on a scheme is stripped on
 *    purpose by the core's `normalizeScheme`, so `--deny-scheme ftp:` matches.
 *    None of `, ; |` or whitespace can: each of them inside a host makes the URL
 *    unparseable, and the scheme and port grammars admit none of them.
 * 2. Is it a character a person plausibly types BETWEEN two list items? This is
 *    what keeps `/ & = ? #` out. They are as void as a semicolon in a value
 *    today, but nobody joins a TLD list with `&`, so an error phrased "not a
 *    value separator" would be answering a question the caller did not ask.
 *    A value shaped like a pasted URL is a per-axis validity problem; this
 *    screen is not the place to litigate it.
 *
 * Whitespace earns its place twice over: `--deny-tld "$(cat tlds.txt)"` is a
 * newline-joined value, and a copy-paste out of a rendered document supplies a
 * no-break space. Both are already covered, because the whitespace this rejects
 * is defined as exactly what `String.prototype.trim` strips — `\s` and `trim`
 * are the same set in the language — so the screen is precisely "the padding
 * that trimming cannot reach because it is in the middle".
 *
 * The `;` case is the comma's case verbatim. It cannot appear on any axis today
 * but it is an RFC 3986 sub-delim that a future path-shaped axis would want, so
 * refusing keeps that door open exactly as LINK-ynozvajn argued. `|` is not in
 * the RFC 3986 grammar at all and is a forbidden host code point besides.
 */
const SEPARATOR = /[,;|\s]/;

/** The same set, in runs, for building the suggested repeated form. */
const SEPARATOR_RUN = /[,;|\s]+/;

/** How to name each refused character in the error the caller reads. */
const SEPARATOR_NAMES = new Map<string, string>([
  [",", "a comma"],
  [";", "a semicolon"],
  ["|", "a vertical bar"],
  [" ", "a space"],
  ["\t", "a tab"],
  ["\n", "a newline"],
  ["\r", "a carriage return"],
]);

/**
 * Reject one joined value on a repeatable list flag, or return.
 *
 * `--deny-tld "com, ru"` is the natural thing to type at a flag that advertises
 * itself as a list, and it is the one shape the CLI cannot honor: `parseArgs`
 * hands it over as ONE value, the literal string `com, ru`. That string is not
 * a TLD, so the deny-list matches nothing while reporting nothing — no error,
 * no warning, exit 0, and a caller who believes a two-TLD policy is in force
 * (LINK-ynozvajn, widened past the comma by LINK-stuiljry). The trim at the
 * core's `normalizedList` choke point closed the neighbouring padded case
 * `--deny-tld " com"` and cannot close this one, because what is in the middle
 * is not padding.
 *
 * Refusing rather than splitting, for three reasons:
 *
 * - It is the same disposition `parsePort` already takes on this same surface:
 *   a value that can never match is a usage error at the boundary where a human
 *   typed it, not a dead deny-list entry the caller never hears about.
 * - Splitting would spend the character repo-wide and permanently, and the two
 *   directions are not symmetrical: a flag that refuses a separator can be
 *   taught to split one later, while a flag that splits cannot be taught to
 *   stop. Refusal is the reversible half of the decision, which is the whole
 *   argument for refusing anything genuinely ambiguous.
 * - The core cannot do it. `normalizeOptions` is contractually total ("Never
 *   throws — inspection must be total"), which is exactly why this lives here.
 *
 * Trimmed before it is screened, so the padded single value LINK-uxkrtcnw
 * deliberately made harmless stays harmless: `--deny-tld " com"` is one TLD
 * with padding the core strips, not two values joined by a space. It shares
 * {@link trimFlagValue} with `parsePort` so the two cannot disagree about where
 * padding ends and the screened middle begins.
 */
function assertNotJoined(flag: string, value: string): void {
  const trimmed = trimFlagValue(value);
  const found = SEPARATOR.exec(trimmed)?.[0];
  if (found === undefined) return;
  const name = SEPARATOR_NAMES.get(found) ?? "a whitespace character";
  const parts = trimmed.split(SEPARATOR_RUN).filter((part) => part !== "");
  const shown = parts.slice(0, SUGGESTION_LIMIT).map((part) => `${flag} ${part}`);
  const suggestion =
    parts.length > SUGGESTION_LIMIT ? `${shown.join(" ")} ...` : shown.join(" ");
  const advice =
    suggestion === ""
      ? `repeat ${flag} once per value`
      : `repeat the flag once per value: ${suggestion}`;
  throw new UsageError(
    `invalid ${flag} value: ${value} (${name} is not a value separator — ${advice})`,
  );
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

  // Every repeatable value flag, enumerated rather than derived: a ninth one
  // added to `options` above has to be added here to inherit the separator
  // refusal, and the omission is visible in the diff. `--deny-port` is screened
  // here too, ahead of `parsePort`, so a joined port list is told about the
  // repeatable form rather than about the valid port range.
  const listValues: ReadonlyArray<readonly [string, readonly string[] | undefined]> = [
    ["--idn-allow", values["idn-allow"]],
    ["--deny-tld", values["deny-tld"]],
    ["--allow-tld", values["allow-tld"]],
    ["--deny-host", values["deny-host"]],
    ["--allow-host", values["allow-host"]],
    ["--allow-scheme", values["allow-scheme"]],
    ["--deny-scheme", values["deny-scheme"]],
    ["--deny-port", values["deny-port"]],
  ];
  for (const [flag, flagValues] of listValues) {
    for (const value of flagValues ?? []) assertNotJoined(flag, value);
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
