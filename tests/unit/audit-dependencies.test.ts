/**
 * LINK-urjaxlrz — contract tests for `tools/audit-dependencies.ts`, the
 * dependency vulnerability audit behind `pnpm audit:deps`.
 *
 * NOTHING HERE OPENS A SOCKET OR SPAWNS A PROCESS. The audited command is a
 * network call, but this suite runs inside `pnpm check`, which is offline and
 * deterministic (and runs inside `tools/verify.sh`, expected to work on a
 * plane). Every registry answer is a fixture and the runner is injected, so a
 * registry outage cannot redden the gate and an advisory being published or
 * withdrawn cannot change a result here.
 *
 * THE FIXTURES ARE TRANSCRIBED FROM A REAL RUN, not invented. `pnpm audit
 * --json` was driven against this workspace on pnpm 11.8.0 while writing this,
 * and the three shapes pinned below are what it actually produced:
 *
 *   - a report: `{advisories: {<id>: {...}}, metadata: {vulnerabilities: {...}}}`
 *   - a failure: `{"error":{"code":"pnpm","message":"fetch failed"}}` on STDOUT,
 *     with exit 1 and an empty stderr — indistinguishable from a finding by exit
 *     code alone, which is the entire reason the wrapper exists
 *   - a pruned report: `--audit-level high` keeps `metadata.vulnerabilities`
 *     intact while deleting every advisory below the threshold from
 *     `advisories`, which is why the policy cannot be expressed by that flag
 *
 * WHAT THIS SUITE CANNOT EXERCISE, stated plainly per the
 * `check-upstream.test.ts` precedent:
 *   - The registry's own behaviour. That the endpoint answers in this shape, and
 *     that it keeps answering in it, is a property of npm; it is pinned here as a
 *     fixture, not verified.
 *   - `pnpm audit`'s exit codes and flag semantics. Both were established by
 *     running the real command by hand (recorded in the header of
 *     `tools/audit-dependencies.ts`). Re-checking them from a test would mean a
 *     network call in the offline gate.
 *   - The process exit codes. `main()` is not exported; what IS pinned is
 *     `fails()`, the two lines it maps over, and every path that throws into the
 *     exit-2 branch.
 *   - Whether an accepted exception is a GOOD decision. The ledger's shape,
 *     expiry and module agreement are checked; the judgement is a human's.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  audit,
  AuditUnavailableError,
  classify,
  fails,
  formatReport,
  isCalendarDate,
  LEDGER_PATH,
  LedgerError,
  loadExceptions,
  parseAuditReport,
  parseExceptions,
  todayUtc,
  type Advisory,
  type AuditRunner,
  type Exception,
} from "../../tools/audit-dependencies.js";

// ─── fixtures, transcribed from the live run ────────────────────────────────

/** One advisory in the registry's wire shape. */
function wireAdvisory(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    findings: [
      {
        version: "3.1.2",
        paths: [".>@modelcontextprotocol/sdk>ajv>fast-uri"],
        dev: false,
        optional: false,
        bundled: false,
      },
    ],
    id: 1145636,
    title: "fast-uri vulnerable to host confusion via literal backslash authority",
    module_name: "fast-uri",
    vulnerable_versions: ">=3.0.0 <=3.1.3",
    patched_versions: ">=3.1.4",
    severity: "high",
    cwe: "CWE-1286",
    github_advisory_id: "GHSA-v2hh-gcrm-f6hx",
    url: "https://github.com/advisories/GHSA-v2hh-gcrm-f6hx",
    ...over,
  };
}

/** A whole report in the wire shape, with `metadata` derived from the advisories. */
function wireReport(advisories: Record<string, unknown>[]): string {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } as Record<string, number>;
  const map: Record<string, unknown> = {};
  for (const [index, advisory] of advisories.entries()) {
    map[String(1_000_000 + index)] = advisory;
    const severity = String(advisory["severity"]);
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return JSON.stringify({
    advisories: map,
    metadata: {
      vulnerabilities: counts,
      dependencies: 97,
      devDependencies: 240,
      optionalDependencies: 106,
      totalDependencies: 337,
    },
  });
}

/** The exact bytes `pnpm audit --json` printed on stdout with an unreachable registry. */
const FETCH_FAILED = '{\n  "error": {\n    "code": "pnpm",\n    "message": "fetch failed"\n  }\n}\n';

/** A runner that replays a fixture. */
function fakeRunner(stdout: string, code = 1, stderr = ""): AuditRunner {
  return {
    async run() {
      return { stdout, stderr, code };
    },
  };
}

function exception(over: Partial<Exception> = {}): Exception {
  return {
    advisory: "GHSA-v2hh-gcrm-f6hx",
    module: "fast-uri",
    reason: "No fixed release reaches us through the sdk; tracked in LINK-xxxxxxxx.",
    reviewBy: "2026-12-01",
    acceptedOn: "2026-08-25",
    ...over,
  };
}

// ─── parseAuditReport ───────────────────────────────────────────────────────

describe("parseAuditReport — reading a real report", () => {
  it("flattens the wire shape into advisories", () => {
    const report = parseAuditReport(wireReport([wireAdvisory()]));
    expect(report.advisories).toHaveLength(1);
    const advisory = report.advisories[0] as Advisory;
    expect(advisory).toMatchObject({
      ghsa: "GHSA-v2hh-gcrm-f6hx",
      module: "fast-uri",
      severity: "high",
      vulnerable: ">=3.0.0 <=3.1.3",
      patched: ">=3.1.4",
      devOnly: false,
    });
    expect(advisory.paths).toEqual([".>@modelcontextprotocol/sdk>ajv>fast-uri"]);
    expect(report.counts.high).toBe(1);
  });

  it("reads an empty report as no vulnerabilities rather than as a failure", () => {
    expect(parseAuditReport(wireReport([])).advisories).toEqual([]);
  });

  it("marks an advisory dev-only only when EVERY finding is dev", () => {
    const allDev = wireAdvisory({
      findings: [{ paths: ["a"], dev: true }, { paths: ["b"], dev: true }],
    });
    const mixed = wireAdvisory({
      findings: [{ paths: ["a"], dev: true }, { paths: ["b"], dev: false }],
    });
    expect((parseAuditReport(wireReport([allDev])).advisories[0] as Advisory).devOnly).toBe(true);
    expect((parseAuditReport(wireReport([mixed])).advisories[0] as Advisory).devOnly).toBe(false);
  });
});

describe("parseAuditReport — a scan that did not happen is never a clean scan", () => {
  it("rejects pnpm's failure envelope, which arrives on STDOUT with exit 1", () => {
    // The property the whole wrapper exists for. `pnpm audit --json
    // --registry=http://127.0.0.1:9/` exits 1 with an EMPTY stderr and this on
    // stdout — byte-identical to what a real finding's exit code looks like.
    expect(() => parseAuditReport(FETCH_FAILED)).toThrow(AuditUnavailableError);
    expect(() => parseAuditReport(FETCH_FAILED)).toThrow(/fetch failed/);
  });

  it("rejects output that is not JSON at all", () => {
    expect(() => parseAuditReport("ERR_PNPM_NO_LOCKFILE  No lockfile found\n")).toThrow(
      AuditUnavailableError,
    );
  });

  it("rejects JSON that is not an object", () => {
    expect(() => parseAuditReport("[]")).toThrow(/not an object/);
    expect(() => parseAuditReport("null")).toThrow(/not an object/);
  });

  it("rejects a report with no advisories map", () => {
    expect(() => parseAuditReport('{"metadata":{"vulnerabilities":{}}}')).toThrow(
      /no `advisories` object/,
    );
  });

  it("rejects a report with no metadata — completeness could not be checked", () => {
    expect(() => parseAuditReport('{"advisories":{}}')).toThrow(/metadata\.vulnerabilities/);
  });

  it("refuses to classify an advisory whose severity it does not know", () => {
    // Silently bucketing an unknown severity into "report only" would turn a
    // future `severity: "urgent"` into a pass.
    const raw = JSON.stringify({
      advisories: { "1": wireAdvisory({ severity: "urgent" }) },
      metadata: { vulnerabilities: { high: 0 } },
    });
    expect(() => parseAuditReport(raw)).toThrow(/unknown severity "urgent"/);
  });

  it("rejects an advisory with no GHSA id — the ledger has nothing to key on", () => {
    const raw = JSON.stringify({
      advisories: { "1": { ...wireAdvisory(), github_advisory_id: "" } },
      metadata: { vulnerabilities: { high: 1 } },
    });
    expect(() => parseAuditReport(raw)).toThrow(/github_advisory_id/);
  });
});

describe("parseAuditReport — a pruned report is not a report", () => {
  it("rejects a report whose metadata counts a severity the advisories map omits", () => {
    // This is the `--audit-level high` signature, measured: 15 advisories become
    // 5, while metadata still says 1 low / 9 moderate / 5 high. Evaluating
    // "report moderate and low" over that would silently report nothing.
    const raw = JSON.stringify({
      advisories: { "1": wireAdvisory() },
      metadata: { vulnerabilities: { info: 0, low: 1, moderate: 9, high: 1, critical: 0 } },
    });
    expect(() => parseAuditReport(raw)).toThrow(AuditUnavailableError);
    expect(() => parseAuditReport(raw)).toThrow(/1 low, 9 moderate/);
    expect(() => parseAuditReport(raw)).toThrow(/filtered/);
  });

  it("does not cry pruning when a severity is listed but counted differently", () => {
    // One advisory can cover several packages, so metadata and the listing are
    // not required to agree numerically. Only "counted, never listed" is proof.
    const raw = JSON.stringify({
      advisories: { "1": wireAdvisory() },
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 4, critical: 0 } },
    });
    expect(parseAuditReport(raw).advisories).toHaveLength(1);
  });
});

// ─── the exception ledger ───────────────────────────────────────────────────

describe("isCalendarDate", () => {
  it.each([
    ["2026-08-25", true],
    ["2028-02-29", true],
    ["2026-02-30", false],
    ["2026-13-01", false],
    ["2026-8-25", false],
    ["soon", false],
    ["2026-08-25T00:00:00Z", false],
  ])("%s → %s", (value, expected) => {
    expect(isCalendarDate(value)).toBe(expected);
  });
});

describe("parseExceptions — an accepted risk must be a recorded decision", () => {
  const wrap = (entries: unknown[]) => JSON.stringify({ exceptions: entries });

  it("accepts a complete entry", () => {
    expect(parseExceptions(wrap([exception()]))).toEqual([exception()]);
  });

  it("accepts an empty ledger", () => {
    expect(parseExceptions(wrap([]))).toEqual([]);
  });

  it("rejects a ledger that is not JSON, or not the right shape", () => {
    expect(() => parseExceptions("{")).toThrow(LedgerError);
    expect(() => parseExceptions("[]")).toThrow(/`exceptions` array/);
    expect(() => parseExceptions('{"exceptions":{}}')).toThrow(/`exceptions` array/);
  });

  it.each(["advisory", "module", "reason", "reviewBy", "acceptedOn"] as const)(
    "rejects an entry missing `%s`",
    (key) => {
      const entry: Record<string, unknown> = { ...exception() };
      delete entry[key];
      expect(() => parseExceptions(wrap([entry]))).toThrow(LedgerError);
    },
  );

  it("rejects an advisory id that is not a GHSA", () => {
    expect(() => parseExceptions(wrap([exception({ advisory: "CVE-2026-1234" })]))).toThrow(
      /must be a GHSA id/,
    );
  });

  it("rejects the same advisory listed twice — one advisory, one decision", () => {
    expect(() => parseExceptions(wrap([exception(), exception()]))).toThrow(/listed twice/);
  });

  it("rejects a placeholder reason", () => {
    // "TODO" or "known issue" is a silent ignore wearing a ledger's clothes.
    expect(() => parseExceptions(wrap([exception({ reason: "known issue" })]))).toThrow(
      /actual reason/,
    );
  });

  it.each(["2026-02-30", "next quarter", "2026-8-1"])("rejects reviewBy %s", (reviewBy) => {
    expect(() => parseExceptions(wrap([exception({ reviewBy })]))).toThrow(/YYYY-MM-DD/);
  });

  it("parses the ledger this repository actually ships", () => {
    // A committed ledger that the tool would reject is a command that cannot run.
    expect(() => parseExceptions(readFileSync(LEDGER_PATH, "utf8"))).not.toThrow();
    expect(loadExceptions()).toEqual([]);
  });

  it("treats a missing ledger as an empty one, not as a failure", () => {
    expect(loadExceptions("/nonexistent/audit-exceptions.json")).toEqual([]);
  });
});

// ─── the policy ─────────────────────────────────────────────────────────────

const NOW = "2026-08-25";

function verdictFor(advisories: Record<string, unknown>[], exceptions: Exception[] = []) {
  return classify(parseAuditReport(wireReport(advisories)), exceptions, NOW);
}

describe("classify — high and critical block, everything below is reported", () => {
  it.each(["high", "critical"] as const)("blocks on a %s advisory", (severity) => {
    const verdict = verdictFor([wireAdvisory({ severity })]);
    expect(verdict.blocking).toHaveLength(1);
    expect(verdict.reportOnly).toEqual([]);
    expect(fails(verdict)).toBe(true);
  });

  it.each(["moderate", "low", "info"] as const)("reports a %s advisory without blocking", (severity) => {
    const verdict = verdictFor([wireAdvisory({ severity })]);
    expect(verdict.blocking).toEqual([]);
    expect(verdict.reportOnly).toHaveLength(1);
    expect(fails(verdict)).toBe(false);
  });

  it("passes on a mixed report whose only blocking severities are absent", () => {
    // The shape `pnpm audit` alone cannot express: exit 0 while still naming the
    // moderate and low findings rather than reducing them to a count.
    const verdict = verdictFor([
      wireAdvisory({ severity: "moderate", module_name: "hono", github_advisory_id: "GHSA-xgm2-5f3f-mvvc" }),
      wireAdvisory({ severity: "low", module_name: "ip-address", github_advisory_id: "GHSA-aaaa-bbbb-cccc" }),
    ]);
    expect(fails(verdict)).toBe(false);
    expect(verdict.reportOnly.map((a) => a.module)).toEqual(["hono", "ip-address"]);
  });

  it("says nothing at all when the report is empty", () => {
    const verdict = verdictFor([]);
    expect(fails(verdict)).toBe(false);
    expect(formatReport(verdict, NOW)).toMatch(/No known vulnerabilities/);
  });
});

describe("classify — the exception ledger", () => {
  it("suppresses a high advisory under a live exception", () => {
    const verdict = verdictFor([wireAdvisory()], [exception({ reviewBy: "2026-12-01" })]);
    expect(verdict.blocking).toEqual([]);
    expect(verdict.excused).toHaveLength(1);
    expect(verdict.stale).toEqual([]);
    expect(fails(verdict)).toBe(false);
  });

  it("stops suppressing ON the review date, not after it", () => {
    // `reviewBy` is the day the decision is due. Due is not still-good.
    const live = verdictFor([wireAdvisory()], [exception({ reviewBy: "2026-08-26" })]);
    const due = verdictFor([wireAdvisory()], [exception({ reviewBy: NOW })]);
    const past = verdictFor([wireAdvisory()], [exception({ reviewBy: "2026-08-24" })]);
    expect(live.excused).toHaveLength(1);
    expect(fails(live)).toBe(false);
    expect(due.lapsed).toHaveLength(1);
    expect(fails(due)).toBe(true);
    expect(past.lapsed).toHaveLength(1);
    expect(fails(past)).toBe(true);
  });

  it("refuses to suppress when the ledger names a different package", () => {
    // A copy-pasted entry must not silently excuse an advisory nobody read.
    const verdict = verdictFor([wireAdvisory()], [exception({ module: "ip-address" })]);
    expect(verdict.mismatched).toHaveLength(1);
    expect(verdict.excused).toEqual([]);
    expect(fails(verdict)).toBe(true);
  });

  it("names an exception that matches nothing, without failing on it", () => {
    // The dependency was fixed or the advisory withdrawn: good news, plus dead
    // weight in the ledger that should be deleted.
    const verdict = verdictFor([], [exception()]);
    expect(verdict.stale).toHaveLength(1);
    expect(fails(verdict)).toBe(false);
  });

  it("does not call an exception stale merely because its advisory was below high", () => {
    const verdict = verdictFor([wireAdvisory({ severity: "moderate" })], [exception()]);
    expect(verdict.stale).toEqual([]);
    expect(verdict.reportOnly).toHaveLength(1);
    expect(fails(verdict)).toBe(false);
  });
});

// ─── the runner seam ────────────────────────────────────────────────────────

describe("audit — pnpm's exit code is never the verdict", () => {
  it("passes on exit 1 when the findings are all below high", async () => {
    // `pnpm audit` exits 1 for a single LOW advisory (its default audit level is
    // `low`). Inheriting that exit code would block on everything.
    const verdict = await audit(fakeRunner(wireReport([wireAdvisory({ severity: "low" })]), 1), [], NOW);
    expect(fails(verdict)).toBe(false);
  });

  it("fails on exit 0 if a high advisory somehow appears in the report", async () => {
    const verdict = await audit(fakeRunner(wireReport([wireAdvisory()]), 0), [], NOW);
    expect(fails(verdict)).toBe(true);
  });

  it("throws on the failure envelope even though its exit code is 1", async () => {
    await expect(audit(fakeRunner(FETCH_FAILED, 1), [], NOW)).rejects.toThrow(AuditUnavailableError);
  });

  it("throws when there is no output to read, and quotes stderr", async () => {
    await expect(audit(fakeRunner("", 1, "ERR_PNPM_FETCH_500"), [], NOW)).rejects.toThrow(
      /no output \(exit 1\).*ERR_PNPM_FETCH_500/s,
    );
  });

  it("throws when the runner cannot start the process", async () => {
    const broken: AuditRunner = {
      async run() {
        throw new AuditUnavailableError("could not run `pnpm audit`: spawn ENOENT");
      },
    };
    await expect(audit(broken, [], NOW)).rejects.toThrow(/spawn ENOENT/);
  });
});

describe("todayUtc", () => {
  it("renders YYYY-MM-DD in UTC", () => {
    expect(todayUtc(new Date("2026-08-25T23:30:00Z"))).toBe("2026-08-25");
    expect(isCalendarDate(todayUtc())).toBe(true);
  });
});

// ─── the report ─────────────────────────────────────────────────────────────

describe("formatReport", () => {
  it("names each blocking advisory and routes the reader to the ledger", () => {
    const out = formatReport(verdictFor([wireAdvisory()]), NOW);
    expect(out).toMatch(/BLOCKING/);
    expect(out).toMatch(/GHSA-v2hh-gcrm-f6hx/);
    expect(out).toMatch(/fast-uri/);
    expect(out).toMatch(/fixed in >=3\.1\.4/);
    expect(out).toMatch(/tools\/audit-exceptions\.json/);
    expect(out).toMatch(/no silent ignore/);
  });

  it("lists the non-blocking advisories instead of counting them", () => {
    // The property `--audit-level high` deletes: which package, which GHSA.
    const out = formatReport(
      verdictFor([
        wireAdvisory({ severity: "moderate", module_name: "hono", github_advisory_id: "GHSA-xgm2-5f3f-mvvc" }),
      ]),
      NOW,
    );
    expect(out).toMatch(/REPORTED, NOT BLOCKING/);
    expect(out).toMatch(/GHSA-xgm2-5f3f-mvvc/);
    expect(out).toMatch(/hono/);
  });

  it("prints the reason and the review date of a live exception", () => {
    const out = formatReport(verdictFor([wireAdvisory()], [exception()]), NOW);
    expect(out).toMatch(/ACCEPTED/);
    expect(out).toMatch(/review by 2026-12-01/);
    expect(out).toMatch(/tracked in LINK-xxxxxxxx/);
    expect(out).toMatch(/Nothing blocking/);
  });

  it("says when an exception lapsed and on what date", () => {
    const out = formatReport(verdictFor([wireAdvisory()], [exception({ reviewBy: "2026-01-01" })]), NOW);
    expect(out).toMatch(/EXPIRED EXCEPTION/);
    expect(out).toMatch(/accepted until 2026-01-01; today is 2026-08-25/);
  });

  it("says when the ledger describes a different package", () => {
    const out = formatReport(verdictFor([wireAdvisory()], [exception({ module: "ip-address" })]), NOW);
    expect(out).toMatch(/LEDGER MISMATCH/);
    expect(out).toMatch(/Not suppressed/);
  });

  it("names stale entries so the ledger does not accumulate", () => {
    const out = formatReport(verdictFor([], [exception()]), NOW);
    expect(out).toMatch(/STALE LEDGER ENTRIES/);
    expect(out).toMatch(/delete them/);
  });

  it("marks a dev-only advisory as such", () => {
    const out = formatReport(
      verdictFor([wireAdvisory({ findings: [{ paths: ["x>nanoid"], dev: true }] })]),
      NOW,
    );
    expect(out).toMatch(/\(dev only;/);
  });
});
