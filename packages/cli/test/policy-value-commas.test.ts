import { describe, expect, it } from "vitest";
import type { InspectResult } from "linklint";
import { parseCli, run, UsageError } from "@linklint/cli";

/**
 * LINK-ynozvajn — what a comma inside one policy-flag value currently means.
 *
 * Every list-taking flag in `packages/cli/src/args.ts` is declared
 * `{ type: "string", multiple: true }`, and nothing anywhere splits on commas.
 * So `--deny-tld "com, ru"` is ONE value, the literal string `com, ru`. The
 * trim added at the core's `normalizedList` choke point (LINK-uxkrtcnw) fixes
 * the PADDED case `--deny-tld " com"` and cannot touch this one: there is
 * nothing to trim, and `com, ru` is not a TLD.
 *
 * Comma-joining is an extremely natural thing to type at a flag that advertises
 * itself as a list, and the two failure shapes it produces are both wrong:
 *
 *   - on a DENY axis the whole list is void — no reason, no warning, exit 0,
 *     and the caller believes a two-value deny-list is in force;
 *   - on an ALLOW axis it is worse than void — the joined string matches
 *     nothing, so a value the caller explicitly listed is reported as NOT
 *     allow-listed.
 *
 * This file pins that behavior exactly as it stands so the change to it is
 * visible as a diff rather than as an absence. The control cases below are the
 * load-bearing half: they show the repeatable form does work, so a failure here
 * is about the comma and not about the axis being broken outright.
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

/** Run `check --json` and return the single result plus the process exit code. */
function check(...argv: string[]): { result: InspectResult; exit: number; codes: string[] } {
  const c = collectors();
  const exit = run(["check", "--json", ...argv], c.out, c.err);
  const parsed = JSON.parse(c.outLines.join("\n")) as InspectResult[];
  const result = parsed[0];
  if (!result) throw new Error("unreachable");
  return { result, exit, codes: result.reasons.map((r) => r.code) };
}

const DOTCOM = "https://a.example.com/";
const EVIL = "https://sub.evil.com/";
const FTP = "ftp://files.example.com/";
const MUNICH = "https://münchen.de/";

/**
 * One list-taking flag, with a comma-joined value whose FIRST element would
 * have been correct on its own. Splitting the string on `", "` yields the
 * working repeatable form, which is what the control cases use.
 */
interface CommaCase {
  flag: string;
  /** The comma-joined value a user would naturally type. */
  joined: string;
  /** The same intent expressed in the form the CLI actually supports. */
  repeated: [string, string];
  url: string;
  /** The policy reason code this axis emits. */
  code: string;
}

/** Deny-shaped axes: the comma makes the whole deny-list match nothing. */
const DENY_AXES: CommaCase[] = [
  {
    flag: "--deny-tld",
    joined: "com, ru",
    repeated: ["com", "ru"],
    url: DOTCOM,
    code: "tld_denied",
  },
  {
    flag: "--deny-host",
    joined: "evil.com, bad.example",
    repeated: ["evil.com", "bad.example"],
    url: EVIL,
    code: "host_denied",
  },
  {
    flag: "--deny-scheme",
    joined: "ftp, gopher",
    repeated: ["ftp", "gopher"],
    url: FTP,
    code: "scheme_denied",
  },
];

/**
 * Allow-shaped axes: the comma makes the allow-list match nothing, so the axis
 * fires against a value the caller listed. `--allow-scheme` reports the same
 * `scheme_denied` code as its deny twin.
 */
const ALLOW_AXES: CommaCase[] = [
  {
    flag: "--allow-tld",
    joined: "com, de",
    repeated: ["com", "de"],
    url: DOTCOM,
    code: "tld_not_allowlisted",
  },
  {
    flag: "--allow-host",
    joined: "evil.com, other.example",
    repeated: ["evil.com", "other.example"],
    url: EVIL,
    code: "host_not_allowlisted",
  },
  {
    flag: "--allow-scheme",
    joined: "ftp, https",
    repeated: ["ftp", "https"],
    url: FTP,
    code: "scheme_denied",
  },
];

describe("LINK-ynozvajn — a comma-joined value arrives as one literal string", () => {
  it.each([...DENY_AXES, ...ALLOW_AXES])(
    "$flag $joined survives parsing as a single unsplit value",
    ({ flag, joined }) => {
      const cli = parseCli(["check", flag, joined, DOTCOM]);
      if (cli.kind !== "check") throw new Error("unreachable");
      const lists = [
        cli.options.denyTlds,
        cli.options.allowTlds,
        cli.options.denyHosts,
        cli.options.allowHosts,
        cli.options.allowSchemes,
        cli.options.denySchemes,
      ];
      expect(lists.flat()).toEqual([joined]);
    },
  );

  it("--idn-allow is the same shape: one value, comma and all", () => {
    const cli = parseCli(["check", "--idn-allow", "münchen.de,köln.de", MUNICH]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.idnAllowlist).toEqual(["münchen.de,köln.de"]);
  });
});

describe("LINK-ynozvajn — a comma-joined deny-list is silently void", () => {
  it.each(DENY_AXES)("$flag $joined reports no $code at all", ({ flag, joined, url, code }) => {
    expect(check(flag, joined, url).codes).not.toContain(code);
  });

  it.each(DENY_AXES)("$flag $joined exits 0 with nothing on stderr", ({ flag, joined, url }) => {
    const c = collectors();
    expect(run(["check", "--json", flag, joined, url], c.out, c.err)).toBe(0);
    expect(c.errLines).toEqual([]);
  });

  it.each(DENY_AXES)(
    "control: $flag repeated does fire $code, so the axis itself works",
    ({ flag, repeated, url, code }) => {
      expect(check(flag, repeated[0], flag, repeated[1], url).codes).toContain(code);
    },
  );
});

describe("LINK-ynozvajn — a comma-joined allow-list rejects its own entries", () => {
  it.each(ALLOW_AXES)(
    "$flag $joined reports $code for a value the caller listed",
    ({ flag, joined, url, code }) => {
      expect(check(flag, joined, url).codes).toContain(code);
    },
  );

  it.each(ALLOW_AXES)(
    "control: $flag repeated allow-lists the URL, so the axis itself works",
    ({ flag, repeated, url, code }) => {
      expect(check(flag, repeated[0], flag, repeated[1], url).codes).not.toContain(code);
    },
  );
});

describe("LINK-ynozvajn — a comma-joined --idn-allow exemption is void", () => {
  it("the IDN block still fires on a domain the caller exempted", () => {
    expect(check("--idn-allow", "münchen.de,köln.de", MUNICH).codes).toContain("idn_host");
  });

  it("control: the repeatable form does exempt it", () => {
    expect(
      check("--idn-allow", "münchen.de", "--idn-allow", "köln.de", MUNICH).codes,
    ).not.toContain("idn_host");
  });
});

describe("LINK-ynozvajn — --deny-port is the one axis that already refuses", () => {
  // `parsePort` rejects anything that is not `\d{1,5}`, so a comma-joined port
  // list is caught today. It is caught for the wrong reason: the message talks
  // about the valid range rather than about the repeatable form the user wanted.
  it("throws UsageError on a comma-joined port list", () => {
    expect(() => parseCli(["check", "--deny-port", "80,8080", DOTCOM])).toThrow(UsageError);
  });

  it("the message is the generic range complaint, not comma-specific advice", () => {
    expect(() => parseCli(["check", "--deny-port", "80,8080", DOTCOM])).toThrow(
      /invalid --deny-port value: 80,8080 \(expected an integer 0-65535\)/,
    );
  });
});
