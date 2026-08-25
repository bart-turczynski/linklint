import { describe, expect, it } from "vitest";
import type { InspectResult } from "linklint";
import { parseCli, run, UsageError } from "@linklint/cli";

/**
 * LINK-ynozvajn — a comma inside one policy-flag value is a usage error.
 *
 * Every list-taking flag in `packages/cli/src/args.ts` is declared
 * `{ type: "string", multiple: true }`, and nothing splits on commas. So
 * `--deny-tld "com, ru"` used to arrive as ONE value, the literal string
 * `com, ru`, with two failure shapes and no way to notice either:
 *
 *   - on a DENY axis the whole list was void — no reason, no warning, exit 0,
 *     and a caller who believed a two-value deny-list was in force;
 *   - on an ALLOW axis it was worse than void — the joined string matched
 *     nothing, so a value the caller explicitly listed came back reported as
 *     NOT allow-listed.
 *
 * The trim at the core's `normalizedList` choke point (LINK-uxkrtcnw) closed
 * the neighbouring padded case `--deny-tld " com"` and could not close this
 * one: there is nothing to trim, and `com, ru` is not a TLD.
 *
 * The CLI now refuses the value instead of splitting it. Splitting would spend
 * the comma permanently — no axis can hold one today, but `,` is an RFC 3986
 * sub-delim that appears freely in paths and query strings, so a future path-
 * or param-shaped axis would need it. Refusal keeps that door open, matches the
 * `parsePort` precedent on this same surface, and stays at the CLI boundary
 * where a human typed the flag: `normalizeOptions` is contractually total and
 * cannot raise a usage error at all.
 *
 * The control cases are the load-bearing half. Every axis asserts that the
 * repeatable form still does exactly what it did, so a failure here is about
 * the comma and not about the refusal having eaten the axis.
 */

function collectors(): {
  out: (s: string) => void;
  err: (s: string) => void;
  outLines: string[];
  errLines: string[];
} {
  const outLines: string[] = [];
  const errLines: string[] = [];
  return { out: (s) => outLines.push(s), err: (s) => errLines.push(s), outLines, errLines };
}

/** Run `check --json` and return the parsed single result and its reason codes. */
function check(...argv: string[]): { result: InspectResult; codes: string[] } {
  const c = collectors();
  run(["check", "--json", ...argv], c.out, c.err);
  const parsed = JSON.parse(c.outLines.join("\n")) as InspectResult[];
  const result = parsed[0];
  if (!result) throw new Error("unreachable");
  return { result, codes: result.reasons.map((r) => r.code) };
}

const DOTCOM = "https://a.example.com/";
const EVIL = "https://sub.evil.com/";
const FTP = "ftp://files.example.com/";
const MUNICH = "https://münchen.de/";

/**
 * One list-taking flag, with a comma-joined value whose elements would each
 * have been correct on their own, plus the repeatable form that expresses the
 * same intent.
 */
interface CommaCase {
  flag: string;
  /** The comma-joined value a user would naturally type. */
  joined: string;
  /** The same intent in the form the CLI supports. */
  repeated: [string, string];
  url: string;
  /** The policy reason code this axis emits. */
  code: string;
  /** Whether the repeatable form makes `code` appear or disappear on `url`. */
  fires: boolean;
}

/**
 * Every repeatable value flag, one bad-input case each. `--deny-port` is in the
 * table for the refusal but not for the reason-code control, since its control
 * needs a ported URL; it gets its own block below.
 */
const AXES: CommaCase[] = [
  {
    flag: "--deny-tld",
    joined: "com, ru",
    repeated: ["com", "ru"],
    url: DOTCOM,
    code: "tld_denied",
    fires: true,
  },
  {
    flag: "--deny-host",
    joined: "evil.com, bad.example",
    repeated: ["evil.com", "bad.example"],
    url: EVIL,
    code: "host_denied",
    fires: true,
  },
  {
    flag: "--deny-scheme",
    joined: "ftp, gopher",
    repeated: ["ftp", "gopher"],
    url: FTP,
    code: "scheme_denied",
    fires: true,
  },
  {
    flag: "--allow-tld",
    joined: "com, de",
    repeated: ["com", "de"],
    url: DOTCOM,
    code: "tld_not_allowlisted",
    fires: false,
  },
  {
    flag: "--allow-host",
    joined: "evil.com, other.example",
    repeated: ["evil.com", "other.example"],
    url: EVIL,
    code: "host_not_allowlisted",
    fires: false,
  },
  {
    flag: "--allow-scheme",
    joined: "ftp, https",
    repeated: ["ftp", "https"],
    url: FTP,
    code: "scheme_denied",
    fires: false,
  },
  {
    flag: "--idn-allow",
    joined: "münchen.de,köln.de",
    repeated: ["münchen.de", "köln.de"],
    url: MUNICH,
    code: "idn_host",
    fires: false,
  },
];

/** The one axis whose values are not strings by the time they reach `options`. */
const PORT_CASE = { flag: "--deny-port", joined: "80,8080", url: "https://example.com:8080/" };

describe("LINK-ynozvajn — a comma-joined value is refused, not silently voided", () => {
  it.each(AXES)("$flag $joined throws UsageError", ({ flag, joined, url }) => {
    expect(() => parseCli(["check", flag, joined, url])).toThrow(UsageError);
  });

  it("--deny-port is screened for the comma before its port-range check", () => {
    expect(() => parseCli(["check", PORT_CASE.flag, PORT_CASE.joined, PORT_CASE.url])).toThrow(
      /a comma is not a value separator/,
    );
  });

  it.each(AXES)(
    "$flag names the offending value and the repeatable form",
    ({ flag, joined, repeated, url }) => {
      expect(() => parseCli(["check", flag, joined, url])).toThrow(
        `invalid ${flag} value: ${joined} (a comma is not a value separator — repeat the flag once per value: ${flag} ${repeated[0]} ${flag} ${repeated[1]})`,
      );
    },
  );

  it.each(AXES)("$flag exits 2 and inspects nothing", ({ flag, joined, url }) => {
    const c = collectors();
    expect(run(["check", "--json", flag, joined, url], c.out, c.err)).toBe(2);
    expect(c.outLines).toEqual([]);
    expect(c.errLines.join("\n")).toContain("a comma is not a value separator");
  });

  it("a comma anywhere in the value is enough, not just a comma-space", () => {
    expect(() => parseCli(["check", "--deny-host", "a.example,b.example", DOTCOM])).toThrow(
      UsageError,
    );
    expect(() => parseCli(["check", "--deny-tld", "com,", DOTCOM])).toThrow(UsageError);
    expect(() => parseCli(["check", "--deny-tld", ",com", DOTCOM])).toThrow(UsageError);
  });

  it("a value that is nothing but commas still gets advice, without an empty example", () => {
    expect(() => parseCli(["check", "--deny-tld", ",,", DOTCOM])).toThrow(
      "invalid --deny-tld value: ,, (a comma is not a value separator — repeat --deny-tld once per value)",
    );
  });

  it("a long joined list elides the suggestion rather than restating all of it", () => {
    expect(() => parseCli(["check", "--deny-tld", "a,b,c,d,e", DOTCOM])).toThrow(
      "repeat the flag once per value: --deny-tld a --deny-tld b --deny-tld c ...",
    );
  });

  it("only the list flags are screened — a comma elsewhere is not this error", () => {
    // `--fail-on` takes one value from a closed set and reports its own problem;
    // a URL positional may hold commas and is the parser's business, not this
    // check's. Neither should be captured by the comma refusal.
    expect(() => parseCli(["check", "--fail-on", "high,low", DOTCOM])).toThrow(/invalid --fail-on/);
    const cli = parseCli(["check", "https://example.com/a,b"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.urls).toEqual(["https://example.com/a,b"]);
  });
});

describe("LINK-ynozvajn — the repeatable form is untouched", () => {
  it.each(AXES)("$flag repeated still lands both values", ({ flag, repeated, url }) => {
    const cli = parseCli(["check", flag, repeated[0], flag, repeated[1], url]);
    if (cli.kind !== "check") throw new Error("unreachable");
    const lists = [
      cli.options.idnAllowlist,
      cli.options.denyTlds,
      cli.options.allowTlds,
      cli.options.denyHosts,
      cli.options.allowHosts,
      cli.options.allowSchemes,
      cli.options.denySchemes,
    ];
    expect(lists.flat()).toEqual([repeated[0], repeated[1]]);
  });

  it.each(AXES.filter((a) => a.fires))(
    "$flag repeated still reports $code",
    ({ flag, repeated, url, code }) => {
      expect(check(flag, repeated[0], flag, repeated[1], url).codes).toContain(code);
    },
  );

  it.each(AXES.filter((a) => !a.fires))(
    "$flag repeated still clears $code",
    ({ flag, repeated, url, code }) => {
      expect(check(flag, repeated[0], flag, repeated[1], url).codes).not.toContain(code);
    },
  );

  it("--deny-port repeated still lands both ports as numbers", () => {
    const cli = parseCli(["check", "--deny-port", "80", "--deny-port", "8080", PORT_CASE.url]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyPorts).toEqual([80, 8080]);
    expect(check("--deny-port", "80", "--deny-port", "8080", PORT_CASE.url).codes).toContain(
      "port_denied",
    );
  });

  it("--deny-port still reports its range problem when there is no comma", () => {
    expect(() => parseCli(["check", "--deny-port", "99999", DOTCOM])).toThrow(
      /invalid --deny-port value: 99999 \(expected an integer 0-65535\)/,
    );
  });

  it("a single comma-free value on every axis parses as it always did", () => {
    const cli = parseCli([
      "check",
      "--deny-tld",
      "tk",
      "--allow-tld",
      "com",
      "--deny-host",
      "evil.com",
      "--allow-host",
      "mycompany.com",
      "--deny-scheme",
      "javascript",
      "--allow-scheme",
      "https",
      "--deny-port",
      "8080",
      "--idn-allow",
      "münchen.de",
      DOTCOM,
    ]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyTlds).toEqual(["tk"]);
    expect(cli.options.allowTlds).toEqual(["com"]);
    expect(cli.options.denyHosts).toEqual(["evil.com"]);
    expect(cli.options.allowHosts).toEqual(["mycompany.com"]);
    expect(cli.options.denySchemes).toEqual(["javascript"]);
    expect(cli.options.allowSchemes).toEqual(["https"]);
    expect(cli.options.denyPorts).toEqual([8080]);
    expect(cli.options.idnAllowlist).toEqual(["münchen.de"]);
  });
});
