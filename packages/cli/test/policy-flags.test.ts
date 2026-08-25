import { describe, expect, it } from "vitest";
import { inspect, type InspectResult } from "linklint";
import { parseCli, run, UsageError } from "@linklint/cli";

/**
 * LINK-okvdbkbk — the CLI's coverage of the policy channel, axis by axis.
 *
 * `packages/core/src/schema/options.ts` declares EIGHT policy axes: `denyTlds`,
 * `allowTlds`, `denyHosts`, `allowHosts`, `allowSchemes`, `denySchemes`,
 * `denyPorts` and `denyNonStandardPorts`. Every one of them is caller-supplied
 * judgment reported at weight 0 — the settled shape §1.1 gives that slot.
 *
 * `docs/architecture.md` §6.1.5 records why the CLI has to carry them: the
 * answer "the caller owns this slot" was "only half true in practice, because
 * `packages/cli/src/args.ts` shipped ZERO policy flags — a `linklint check`
 * user lost the signal with no lever at all". Two flags were added there. This
 * file pins the state of ALL eight, so the gap between the library and the
 * tool's main surface is a fact the suite asserts rather than one a reader has
 * to rediscover.
 */

function collectors(): { out: (s: string) => void; err: (s: string) => void; outLines: string[] } {
  const outLines: string[] = [];
  return { out: (s) => outLines.push(s), err: () => {}, outLines };
}

const json = (lines: string[]): InspectResult => {
  const parsed = JSON.parse(lines.join("\n")) as InspectResult[];
  const el = parsed[0];
  if (!el) throw new Error("unreachable");
  return el;
};

function check(...argv: string[]): InspectResult {
  const c = collectors();
  run(["check", "--json", ...argv], c.out, c.err);
  return json(c.outLines);
}

const codes = (result: InspectResult): string[] => result.reasons.map((r) => r.code);

const TK = "https://mycompany.tk/";
const EVIL = "https://sub.evil.com/";
const FTP = "ftp://files.example.com/";
const PORTED = "https://example.com:8080/";

/** The eight policy axes, and the CLI flag each one is (or is not) reachable by. */
const WIRED = ["--deny-tld", "--allow-tld"] as const;
const UNWIRED = [
  "--deny-host",
  "--allow-host",
  "--allow-scheme",
  "--deny-scheme",
  "--deny-port",
  "--deny-non-standard-ports",
] as const;

describe("the TLD axis is reachable from `linklint check`", () => {
  it.each(WIRED)("%s is a recognized flag", (flag) => {
    expect(() => parseCli(["check", flag, "tk", "https://x.example"])).not.toThrow();
  });

  it("--deny-tld emits tld_denied at weight 0 and leaves the score alone", () => {
    const el = check("--deny-tld", "tk", TK);
    const denied = el.reasons.find((r) => r.code === "tld_denied");
    expect(denied?.weight).toBe(0);
    expect(el.score).toBe(0);
  });

  it("--allow-tld emits tld_not_allowlisted at weight 0", () => {
    const el = check("--allow-tld", "com", TK);
    expect(el.reasons.find((r) => r.code === "tld_not_allowlisted")?.weight).toBe(0);
    expect(el.score).toBe(0);
  });
});

describe("the other six axes are NOT reachable from `linklint check`", () => {
  // The library has every one of these; the tool has none of them. This is the
  // half of LINK-brsntven's remedy that was left behind.
  it.each(UNWIRED)("%s is an unrecognized flag", (flag) => {
    expect(() => parseCli(["check", flag, "evil.com", "https://x.example"])).toThrow(UsageError);
  });

  it.each(UNWIRED)("%s is absent from --help", (flag) => {
    const c = collectors();
    run(["--help"], c.out, c.err);
    expect(c.outLines.join("\n")).not.toContain(flag);
  });

  it("the host axis exists in the library and is unreachable from the CLI", () => {
    expect(codes(inspect(EVIL, { denyHosts: ["evil.com"] }))).toContain("host_denied");
    expect(codes(check(EVIL))).not.toContain("host_denied");
  });

  it("the scheme axis exists in the library and is unreachable from the CLI", () => {
    expect(codes(inspect(FTP, { denySchemes: ["ftp"] }))).toContain("scheme_denied");
    expect(codes(check(FTP))).not.toContain("scheme_denied");
  });

  it("the port axis exists in the library and is unreachable from the CLI", () => {
    expect(codes(inspect(PORTED, { denyPorts: [8080] }))).toContain("port_denied");
    expect(codes(inspect(PORTED, { denyNonStandardPorts: true }))).toContain("port_denied");
    expect(codes(check(PORTED))).not.toContain("port_denied");
  });
});

describe("no policy flag means no policy channel at all", () => {
  it("a bare check is byte-identical to a default inspect", () => {
    expect(check(TK)).toEqual(inspect(TK));
    expect(check(TK).checksRun).not.toContain("policy");
  });
});
