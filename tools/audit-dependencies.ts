/**
 * `pnpm audit:deps` — the workspace's dependency vulnerability audit
 * (LINK-urjaxlrz).
 *
 * WHY THIS EXISTS. Nothing in this repository scans the working tree or the
 * lockfile. The Socket badge analyses the *published* npm package, which says
 * nothing about a dev dependency, a transitive one, or a lockfile entry that
 * never ships. `pnpm audit` closes that gap: it posts the resolved tree —
 * production, dev and optional, every workspace project — to the registry's
 * advisory endpoint and reports what is known-vulnerable.
 *
 * NEVER PUT THIS IN THE PRE-PUSH HOOK OR `pnpm check`. `tools/verify.sh` is the
 * primary gate and is expected to work on a plane; this command makes a network
 * call, and its answer changes when the advisory database changes rather than
 * when the tree does. It is a separately-invoked check, exactly like
 * `pnpm data:upstream-check` (CONTRIBUTING.md §"The verify gate").
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY A WRAPPER RATHER THAN A BARE `pnpm audit --audit-level high`
 *
 * The obvious one-liner cannot express this policy. Both reasons were driven
 * against pnpm 11.8.0 on this tree, not read out of documentation:
 *
 *   1. `--audit-level` PRUNES THE REPORT, it does not merely set a threshold.
 *      With 1 low / 9 moderate / 5 high / 0 critical present:
 *
 *        pnpm audit --json                     → 15 advisories listed, exit 1
 *        pnpm audit --json --audit-level high  →  5 advisories listed, exit 1
 *        pnpm audit --json --audit-level critical → 0 advisories listed, exit 0
 *
 *      `metadata.vulnerabilities` keeps the full counts in every case, so the
 *      moderate and low findings survive only as aggregate numbers. "Report
 *      moderate/low without blocking" needs the advisory records — which package,
 *      which GHSA, which patched range — and the flag deletes them. pnpm's own
 *      help says "only PRINT advisories with severity greater than or equal to".
 *
 *   2. EXIT 1 MEANS BOTH "FOUND SOMETHING" AND "COULD NOT ASK".
 *
 *        pnpm audit --json --registry=http://127.0.0.1:9/  → exit 1
 *        stdout: {"error":{"code":"pnpm","message":"fetch failed"}}
 *
 *      Identical exit code, and stderr is empty. The only thing that separates a
 *      real result from a failed scan is the SHAPE OF STDOUT, which means
 *      something has to read it. `--ignore-registry-errors` exists and does the
 *      opposite of what is wanted here: it turns a failed scan into exit 0,
 *      which is precisely the fail-open this check is built to refuse.
 *
 * So the wrapper runs `pnpm audit --json` with NO `--audit-level`, applies the
 * severity policy itself over the complete advisory list, and reads stdout to
 * tell a scan that ran from one that did not.
 *
 * IT ALSO REFUSES A PRUNED REPORT. If `metadata.vulnerabilities` records a
 * severity that the `advisories` map does not list at all, the report was
 * filtered before it got here (someone added `--audit-level`, or a future pnpm
 * changed the default) and the policy cannot be evaluated over it. That is
 * exit 2, not a pass.
 *
 * EXCEPTIONS ARE A LEDGER, NOT A FLAG. `pnpm audit --ignore GHSA-…` is a silent
 * ignore: it carries no reason, no date, and no expiry, and it lives in a
 * command line nobody reads. Accepted risk is recorded in
 * `tools/audit-exceptions.json` instead — advisory, module, reason, and a
 * `reviewBy` date. When that date passes the exception stops suppressing and the
 * finding blocks again, so an accepted risk cannot become a permanent one by
 * being forgotten.
 *
 * EXIT CODES — three, because "could not scan" must never read as "all clear":
 *   0  no blocking finding: nothing high/critical outside a live exception
 *   1  at least one high or critical advisory is unexcused, or its exception has
 *      lapsed. Moderate, low and info are reported here too, and never block.
 *   2  the audit could not be evaluated: no network, a registry error, an
 *      unparseable or pruned report, an unclassifiable advisory, or an invalid
 *      exception ledger.
 *
 * Usage:
 *   pnpm audit:deps   # scan, apply the ledger, report. No flags: the policy is
 *                     # the file, not the invocation.
 */
import { spawn } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Repository root, resolved from this file rather than from `process.cwd()`. */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Where accepted risk is recorded. See the header. */
export const LEDGER_PATH = join(REPO_ROOT, "tools", "audit-exceptions.json");

/** npm advisory severities, ascending. */
export const SEVERITIES = ["info", "low", "moderate", "high", "critical"] as const;

export type Severity = (typeof SEVERITIES)[number];

/**
 * The severities that fail the command. Everything below is reported and does
 * not block — the issue's policy, and the reason `--audit-level` alone is not
 * enough (it would delete the non-blocking half of the report).
 */
export const BLOCKING: ReadonlySet<Severity> = new Set<Severity>(["high", "critical"]);

/** Thrown when the audit could not be evaluated at all. Always exit 2. */
export class AuditUnavailableError extends Error {
  override readonly name = "AuditUnavailableError";
}

/** Thrown when the exception ledger cannot be read as policy. Also exit 2. */
export class LedgerError extends Error {
  override readonly name = "LedgerError";
}

/** One advisory, flattened out of the registry's report shape. */
export interface Advisory {
  /** `github_advisory_id`, e.g. `GHSA-v2hh-gcrm-f6hx`. The ledger keys on this. */
  ghsa: string;
  /** Vulnerable package, e.g. `fast-uri`. */
  module: string;
  severity: Severity;
  title: string;
  url: string;
  /** Semver range that is vulnerable, verbatim from the report. */
  vulnerable: string;
  /** Semver range that is not, verbatim. Empty when upstream has no fix. */
  patched: string;
  /** Dependency paths the vulnerable version was reached through. */
  paths: readonly string[];
  /** True only when EVERY finding for this advisory is dev-only. */
  devOnly: boolean;
}

/** A parsed `pnpm audit --json` report. */
export interface AuditReport {
  advisories: readonly Advisory[];
  /** `metadata.vulnerabilities`, used to detect a pruned report. */
  counts: Readonly<Record<Severity, number>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

function requireString(source: Record<string, unknown>, key: string, where: string): string {
  const value = source[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new AuditUnavailableError(`${where}: missing or empty \`${key}\``);
  }
  return value;
}

/**
 * Parse the stdout of `pnpm audit --json`.
 *
 * Throws {@link AuditUnavailableError} rather than returning a partial result,
 * because every failure here is a scan that did not happen or a report that
 * cannot be reasoned about — and the whole point of the command is that neither
 * of those is a pass. In particular:
 *
 *   - pnpm's failure envelope, `{"error":{"code":…,"message":…}}`, which it
 *     prints on stdout with exit 1 and an EMPTY stderr when the registry cannot
 *     be reached. Nothing but this shape distinguishes it from a real finding.
 *   - a severity string the policy does not know. An advisory that cannot be
 *     classified must not fall through to "report only".
 *   - a report whose `metadata` counts a severity the `advisories` map does not
 *     list at all: it was pruned by `--audit-level` before it reached here.
 */
export function parseAuditReport(stdout: string): AuditReport {
  let body: unknown;
  try {
    body = JSON.parse(stdout);
  } catch (error) {
    const head = stdout.trim().slice(0, 200);
    throw new AuditUnavailableError(
      `pnpm audit did not return JSON (${String(error)}). First 200 bytes: ${JSON.stringify(head)}`,
    );
  }
  if (!isRecord(body)) {
    throw new AuditUnavailableError("pnpm audit returned JSON that is not an object");
  }
  if ("error" in body) {
    const envelope = isRecord(body["error"]) ? body["error"] : {};
    const message = typeof envelope["message"] === "string" ? envelope["message"] : "unknown error";
    const code = typeof envelope["code"] === "string" ? envelope["code"] : "unknown";
    throw new AuditUnavailableError(`pnpm audit reported an error (${code}): ${message}`);
  }

  const rawAdvisories = body["advisories"];
  if (!isRecord(rawAdvisories)) {
    throw new AuditUnavailableError("pnpm audit returned no `advisories` object");
  }

  const advisories: Advisory[] = [];
  for (const [key, raw] of Object.entries(rawAdvisories)) {
    const where = `advisory ${key}`;
    if (!isRecord(raw)) throw new AuditUnavailableError(`${where}: not an object`);
    const severity = raw["severity"];
    if (!isSeverity(severity)) {
      throw new AuditUnavailableError(
        `${where}: unknown severity ${JSON.stringify(severity)} — refusing to classify it`,
      );
    }
    const findings = Array.isArray(raw["findings"]) ? raw["findings"] : [];
    const paths: string[] = [];
    let devOnly = findings.length > 0;
    for (const finding of findings) {
      if (!isRecord(finding)) continue;
      if (finding["dev"] !== true) devOnly = false;
      const found = finding["paths"];
      if (Array.isArray(found)) {
        for (const path of found) if (typeof path === "string") paths.push(path);
      }
    }
    advisories.push({
      ghsa: requireString(raw, "github_advisory_id", where),
      module: requireString(raw, "module_name", where),
      severity,
      title: typeof raw["title"] === "string" ? raw["title"] : "(no title)",
      url: typeof raw["url"] === "string" ? raw["url"] : "",
      vulnerable: typeof raw["vulnerable_versions"] === "string" ? raw["vulnerable_versions"] : "",
      patched: typeof raw["patched_versions"] === "string" ? raw["patched_versions"] : "",
      paths,
      devOnly,
    });
  }

  const counts = readCounts(body["metadata"]);
  assertNotPruned(advisories, counts);
  return { advisories, counts };
}

/** Read `metadata.vulnerabilities`; its absence means completeness cannot be checked. */
function readCounts(metadata: unknown): Record<Severity, number> {
  if (!isRecord(metadata) || !isRecord(metadata["vulnerabilities"])) {
    throw new AuditUnavailableError(
      "pnpm audit returned no `metadata.vulnerabilities` — the report's completeness cannot be checked",
    );
  }
  const raw = metadata["vulnerabilities"];
  const counts = {} as Record<Severity, number>;
  for (const severity of SEVERITIES) {
    const value = raw[severity];
    counts[severity] = typeof value === "number" && Number.isFinite(value) ? value : 0;
  }
  return counts;
}

/**
 * Refuse a report that `metadata` says has findings the `advisories` map does
 * not carry — the signature of `--audit-level` having pruned it.
 *
 * The test is "counted but not listed at all", never "counted more times than
 * listed": one advisory can cover several packages, so the two numbers are not
 * required to agree. Zero listed against a non-zero count cannot be explained
 * that way, and it is exactly what every `--audit-level` run produces.
 */
function assertNotPruned(
  advisories: readonly Advisory[],
  counts: Readonly<Record<Severity, number>>,
): void {
  const pruned = SEVERITIES.filter(
    (severity) => counts[severity] > 0 && !advisories.some((a) => a.severity === severity),
  );
  if (pruned.length > 0) {
    throw new AuditUnavailableError(
      `pnpm audit reported ${pruned.map((s) => `${counts[s]} ${s}`).join(", ")} in metadata but ` +
        "listed no such advisory — the report was filtered (`--audit-level`?) and this policy " +
        "cannot be evaluated over a filtered report",
    );
  }
}

/** One accepted risk, as recorded in the ledger. */
export interface Exception {
  /** GHSA id this excuses. Matched exactly against {@link Advisory.ghsa}. */
  advisory: string;
  /** The package it is accepted for, asserted against the advisory. */
  module: string;
  /** Why the risk is accepted. Free prose, required, and printed on every run. */
  reason: string;
  /** `YYYY-MM-DD`. On and after this date the exception stops suppressing. */
  reviewBy: string;
  /** `YYYY-MM-DD` the exception was accepted. */
  acceptedOn: string;
}

const GHSA = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** True when `value` is a real calendar date written `YYYY-MM-DD`. */
export function isCalendarDate(value: string): boolean {
  const m = ISO_DATE.exec(value);
  if (m === null) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return (
    !Number.isNaN(date.getTime()) &&
    date.getUTCFullYear() === Number(m[1]) &&
    date.getUTCMonth() + 1 === Number(m[2]) &&
    date.getUTCDate() === Number(m[3])
  );
}

/**
 * Parse the exception ledger.
 *
 * Every rule below throws rather than skipping the entry. An exception is a
 * decision to keep shipping a known vulnerability; a malformed one means the
 * policy is not known, and an unknown policy is not a pass — so it lands on
 * exit 2 with the rest of the cannot-evaluate cases.
 */
export function parseExceptions(text: string): Exception[] {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch (error) {
    throw new LedgerError(`${LEDGER_PATH} is not valid JSON: ${String(error)}`);
  }
  if (!isRecord(body) || !Array.isArray(body["exceptions"])) {
    throw new LedgerError(`${LEDGER_PATH} must be an object with an \`exceptions\` array`);
  }

  const exceptions: Exception[] = [];
  const seen = new Set<string>();
  for (const [index, raw] of body["exceptions"].entries()) {
    const where = `exception #${index + 1}`;
    if (!isRecord(raw)) throw new LedgerError(`${where}: not an object`);

    const read = (key: string): string => {
      const value = raw[key];
      if (typeof value !== "string" || value.trim().length === 0) {
        throw new LedgerError(`${where}: \`${key}\` is required and must be a non-empty string`);
      }
      return value.trim();
    };

    const advisory = read("advisory");
    if (!GHSA.test(advisory)) {
      throw new LedgerError(`${where}: \`advisory\` must be a GHSA id, got ${JSON.stringify(advisory)}`);
    }
    if (seen.has(advisory)) {
      throw new LedgerError(`${where}: ${advisory} is listed twice — one advisory, one decision`);
    }
    seen.add(advisory);

    const reason = read("reason");
    if (reason.length < 20) {
      throw new LedgerError(
        `${where}: \`reason\` is ${reason.length} characters — an accepted vulnerability needs an ` +
          "actual reason, not a placeholder",
      );
    }

    for (const key of ["reviewBy", "acceptedOn"] as const) {
      if (!isCalendarDate(read(key))) {
        throw new LedgerError(`${where}: \`${key}\` must be a real YYYY-MM-DD date`);
      }
    }

    exceptions.push({
      advisory,
      module: read("module"),
      reason,
      reviewBy: read("reviewBy"),
      acceptedOn: read("acceptedOn"),
    });
  }
  return exceptions;
}

/** Read the ledger from disk. A missing file is an empty ledger, not an error. */
export function loadExceptions(path: string = LEDGER_PATH): Exception[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new LedgerError(`${path} could not be read: ${String(error)}`);
  }
  return parseExceptions(text);
}

/** An advisory paired with the ledger entry that spoke to it. */
export interface Excused {
  advisory: Advisory;
  exception: Exception;
}

/** What the policy makes of one report. */
export interface Verdict {
  /** High/critical with no live exception. Fails the command. */
  blocking: readonly Advisory[];
  /** High/critical whose exception has lapsed. Also fails the command. */
  lapsed: readonly Excused[];
  /** High/critical suppressed by a live exception. Printed, does not fail. */
  excused: readonly Excused[];
  /** Everything below high. Printed, never fails. */
  reportOnly: readonly Advisory[];
  /** Ledger entries matching no advisory in this report. Printed, does not fail. */
  stale: readonly Exception[];
  /** Ledger entries whose `module` disagrees with the advisory's. Fails: the
   *  ledger is describing something other than what it suppresses. */
  mismatched: readonly Excused[];
}

/**
 * Apply the severity policy and the ledger to a report.
 *
 * `today` is passed in rather than read from the clock so expiry is testable
 * without freezing time. Expiry is inclusive of the review date — `reviewBy` is
 * the day the decision is due, so on that day it is due, not still good.
 */
export function classify(
  report: AuditReport,
  exceptions: readonly Exception[],
  today: string,
): Verdict {
  const byGhsa = new Map(exceptions.map((e) => [e.advisory, e]));
  const matched = new Set<string>();

  const blocking: Advisory[] = [];
  const lapsed: Excused[] = [];
  const excused: Excused[] = [];
  const mismatched: Excused[] = [];
  const reportOnly: Advisory[] = [];

  for (const advisory of report.advisories) {
    const exception = byGhsa.get(advisory.ghsa);
    if (exception !== undefined) matched.add(advisory.ghsa);

    if (!BLOCKING.has(advisory.severity)) {
      reportOnly.push(advisory);
      continue;
    }
    if (exception === undefined) {
      blocking.push(advisory);
      continue;
    }
    if (exception.module !== advisory.module) {
      mismatched.push({ advisory, exception });
      continue;
    }
    if (exception.reviewBy <= today) lapsed.push({ advisory, exception });
    else excused.push({ advisory, exception });
  }

  return {
    blocking,
    lapsed,
    excused,
    reportOnly,
    stale: exceptions.filter((e) => !matched.has(e.advisory)),
    mismatched,
  };
}

/** Whether a verdict fails the command. */
export function fails(verdict: Verdict): boolean {
  return verdict.blocking.length > 0 || verdict.lapsed.length > 0 || verdict.mismatched.length > 0;
}

function describe(advisory: Advisory): string {
  const scope = advisory.devOnly ? "dev only" : "runtime";
  const fix = advisory.patched === "" ? "no fix published" : `fixed in ${advisory.patched}`;
  return (
    `  ${advisory.severity.toUpperCase()}  ${advisory.module}  ${advisory.ghsa}  (${scope}; ${fix})\n` +
    `    ${advisory.title}\n` +
    (advisory.url === "" ? "" : `    ${advisory.url}\n`) +
    (advisory.paths.length === 0 ? "" : `    via ${advisory.paths[0] as string}\n`)
  );
}

/** Render the whole report: what blocks, what was excused, what is only noted. */
export function formatReport(verdict: Verdict, today: string): string {
  const out: string[] = [];

  if (verdict.blocking.length > 0) {
    out.push(`BLOCKING — ${verdict.blocking.length} high/critical advisory(ies) with no accepted exception:\n`);
    for (const advisory of verdict.blocking) out.push(describe(advisory));
  }

  for (const { advisory, exception } of verdict.lapsed) {
    out.push(
      `EXPIRED EXCEPTION — ${exception.advisory} was accepted until ${exception.reviewBy}; today is ${today}.\n` +
        `    reason on file: ${exception.reason}\n`,
    );
    out.push(describe(advisory));
  }

  for (const { advisory, exception } of verdict.mismatched) {
    out.push(
      `LEDGER MISMATCH — ${exception.advisory} is recorded against \`${exception.module}\` but the ` +
        `advisory is for \`${advisory.module}\`. Not suppressed.\n`,
    );
    out.push(describe(advisory));
  }

  if (verdict.excused.length > 0) {
    out.push(`ACCEPTED — ${verdict.excused.length} high/critical advisory(ies) under a live exception:\n`);
    for (const { advisory, exception } of verdict.excused) {
      out.push(describe(advisory));
      out.push(`    accepted ${exception.acceptedOn}, review by ${exception.reviewBy}: ${exception.reason}\n`);
    }
  }

  if (verdict.reportOnly.length > 0) {
    out.push(
      `REPORTED, NOT BLOCKING — ${verdict.reportOnly.length} advisory(ies) below high. ` +
        "These do not fail the command; they are here so the number is a list and not a count:\n",
    );
    for (const advisory of verdict.reportOnly) out.push(describe(advisory));
  }

  if (verdict.stale.length > 0) {
    out.push(
      `STALE LEDGER ENTRIES — ${verdict.stale.length} exception(s) match no advisory in this report. ` +
        "Either the dependency moved or the advisory was withdrawn; delete them:\n",
    );
    for (const exception of verdict.stale) {
      out.push(`  ${exception.advisory}  ${exception.module}  (accepted ${exception.acceptedOn})\n`);
    }
  }

  if (out.length === 0) {
    return "No known vulnerabilities in the workspace lockfile (production, dev and optional).\n";
  }

  out.push(
    fails(verdict)
      ? "\nFix the dependency, or record the accepted risk in tools/audit-exceptions.json with a\n" +
          "reason and a reviewBy date. There is no silent ignore.\n"
      : "\nNothing blocking.\n",
  );
  return out.join("\n");
}

/** The audit invocation, injected so tests never spawn a process or open a socket. */
export interface AuditRunner {
  run(): Promise<{ stdout: string; stderr: string; code: number | null }>;
}

/**
 * The real `pnpm audit --json`.
 *
 * Deliberately WITHOUT `--audit-level`: the flag prunes the advisory list (see
 * the header), and this command needs the whole list to report the non-blocking
 * half. Deliberately without `--ignore` too — exceptions are the ledger.
 */
export function pnpmAudit(cwd: string = REPO_ROOT): AuditRunner {
  return {
    run() {
      return new Promise((resolve, reject) => {
        const child = spawn("pnpm", ["audit", "--json"], {
          cwd,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk: string) => {
          stdout += chunk;
        });
        child.stderr.on("data", (chunk: string) => {
          stderr += chunk;
        });
        child.on("error", (error) => {
          reject(new AuditUnavailableError(`could not run \`pnpm audit\`: ${String(error)}`));
        });
        child.on("close", (code) => {
          resolve({ stdout, stderr, code });
        });
      });
    },
  };
}

/**
 * Run the scan and apply the policy.
 *
 * pnpm's own exit code is deliberately NOT the verdict — it is 1 both for a
 * finding and for a failed registry call — so it is used only as corroboration
 * when stdout is empty, which is the one case the parser has nothing to read.
 */
export async function audit(
  runner: AuditRunner,
  exceptions: readonly Exception[],
  today: string,
): Promise<Verdict> {
  const { stdout, stderr, code } = await runner.run();
  if (stdout.trim().length === 0) {
    throw new AuditUnavailableError(
      `pnpm audit produced no output (exit ${String(code)}).` +
        (stderr.trim() === "" ? "" : ` stderr: ${stderr.trim().slice(0, 400)}`),
    );
  }
  return classify(parseAuditReport(stdout), exceptions, today);
}

/** Today in UTC as `YYYY-MM-DD`. */
export function todayUtc(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

async function main(): Promise<number> {
  const today = todayUtc();
  process.stdout.write(
    "Auditing the workspace lockfile (production, dev and optional) against the npm advisory database.\n" +
      "This is a network call and is deliberately not part of `pnpm check`.\n\n",
  );

  let verdict: Verdict;
  try {
    verdict = await audit(pnpmAudit(), loadExceptions(), today);
  } catch (error) {
    if (error instanceof AuditUnavailableError || error instanceof LedgerError) {
      process.stderr.write(`${error.message}\n`);
      process.stderr.write("Nothing was verified — this is not a clean result.\n");
      return 2;
    }
    throw error;
  }

  process.stdout.write(formatReport(verdict, today));
  return fails(verdict) ? 1 : 0;
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  realpathSync(invokedPath) === realpathSync(fileURLToPath(import.meta.url))
) {
  process.exitCode = await main();
}
