import { describe, expect, it } from "vitest";
import type { InspectResult } from "linklint";
import { parseCli, run } from "@linklint/cli";

/**
 * LINK-stuiljry — the residual of LINK-ynozvajn: a policy value joined by
 * anything OTHER than a comma.
 *
 * LINK-ynozvajn scoped itself to the comma and said so. Every other joining
 * character a caller might reach for is still handed to `parseArgs` as ONE
 * value, matches nothing on any axis, and is reported nowhere:
 *
 *     linklint check --deny-tld "com ru" https://a.example.com/   ->  exit 0
 *
 * THIS FILE PINS THAT AS IT STANDS TODAY — silently void — so that the change
 * which closes it has something to invert. Read the assertions below as a
 * description of a fail-open, not as a specification of desired behavior.
 *
 * The two failure shapes are the same ones the comma had:
 *
 *   - on a DENY axis the list is void: the reason the repeated form produces
 *     does not appear, and nothing says so;
 *   - on an ALLOW axis it is worse than void: the joined string matches
 *     nothing, so a value the caller explicitly listed comes back reported as
 *     NOT allow-listed — and `--idn-allow` behaves as an allow axis here, its
 *     exemption silently failing to apply.
 *
 * `--deny-port` is the one axis already loud for every separator, because
 * `parsePort` admits only digits. It is pinned separately: loud, but answering
 * a question about separators with advice about the port range.
 *
 * The control blocks at the bottom are the load-bearing half. They fix the
 * characters that DO legitimately appear in a matching value today, so that a
 * later separator refusal cannot quietly eat one of them.
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

/** Run `check --json` and return the exit code, reason codes and stderr. */
function check(...argv: string[]): {
  exit: 0 | 1 | 2;
  result: InspectResult;
  codes: string[];
  errLines: string[];
} {
  const c = collectors();
  const exit = run(["check", "--json", ...argv], c.out, c.err);
  const parsed = JSON.parse(c.outLines.join("\n")) as InspectResult[];
  const result = parsed[0];
  if (!result) throw new Error("unreachable");
  return { exit, result, codes: result.reasons.map((r) => r.code), errLines: c.errLines };
}

const DOTCOM = "https://a.example.com/";
const EVIL = "https://sub.evil.com/";
const FTP = "ftp://files.example.com/";
const MUNICH = "https://münchen.de/";

/** One repeatable value flag with two values that are each correct on their own. */
interface Axis {
  flag: string;
  values: [string, string];
  url: string;
  /** The policy reason code this axis emits. */
  code: string;
  /** Whether the repeatable form makes `code` appear (deny) or disappear (allow). */
  fires: boolean;
}

/**
 * The seven string-valued repeatable flags. `--deny-port` is the eighth and
 * gets its own block: its values stop being strings at `parsePort`.
 */
const AXES: Axis[] = [
  { flag: "--deny-tld", values: ["com", "ru"], url: DOTCOM, code: "tld_denied", fires: true },
  {
    flag: "--deny-host",
    values: ["evil.com", "bad.example"],
    url: EVIL,
    code: "host_denied",
    fires: true,
  },
  {
    flag: "--deny-scheme",
    values: ["ftp", "gopher"],
    url: FTP,
    code: "scheme_denied",
    fires: true,
  },
  {
    flag: "--allow-tld",
    values: ["com", "de"],
    url: DOTCOM,
    code: "tld_not_allowlisted",
    fires: false,
  },
  {
    flag: "--allow-host",
    values: ["evil.com", "other.example"],
    url: EVIL,
    code: "host_not_allowlisted",
    fires: false,
  },
  {
    flag: "--allow-scheme",
    values: ["ftp", "https"],
    url: FTP,
    code: "scheme_denied",
    fires: false,
  },
  {
    flag: "--idn-allow",
    values: ["münchen.de", "köln.de"],
    url: MUNICH,
    code: "idn_host",
    fires: false,
  },
];

/**
 * The candidate separators, named as a caller would describe them. Every one is
 * a character a person plausibly types between two list items, and none of them
 * can occur in a value that matches any axis today — a space, semicolon or
 * vertical bar inside a host makes the URL unparseable outright, and the scheme
 * and port grammars admit none of them.
 */
const SEPARATORS: ReadonlyArray<{ name: string; char: string }> = [
  { name: "space", char: " " },
  { name: "tab", char: "\t" },
  { name: "newline", char: "\n" },
  { name: "no-break space", char: " " },
  { name: "semicolon", char: ";" },
  { name: "vertical bar", char: "|" },
];

/** Every (axis, separator) pair, flattened so each is its own named case. */
const JOINED = AXES.flatMap((axis) =>
  SEPARATORS.map((sep) => ({
    ...axis,
    sep: sep.name,
    joined: axis.values.join(sep.char),
  })),
);

describe("LINK-stuiljry — a non-comma-joined value is accepted and then silently void", () => {
  it.each(JOINED)("$flag joined by $sep raises no usage error", ({ flag, joined, url }) => {
    expect(() => parseCli(["check", flag, joined, url])).not.toThrow();
  });

  it.each(JOINED)("$flag joined by $sep arrives as one literal value", ({ flag, joined, url }) => {
    const cli = parseCli(["check", flag, joined, url]);
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
    expect(lists.flat()).toEqual([joined]);
  });

  it.each(JOINED.filter((c) => c.fires))(
    "$flag joined by $sep loses $code that the repeated form reports",
    ({ flag, joined, values, url, code }) => {
      expect(check(flag, values[0], flag, values[1], url).codes).toContain(code);
      expect(check(flag, joined, url).codes).not.toContain(code);
    },
  );

  it.each(JOINED.filter((c) => !c.fires))(
    "$flag joined by $sep still reports $code that the repeated form clears",
    ({ flag, joined, values, url, code }) => {
      expect(check(flag, values[0], flag, values[1], url).codes).not.toContain(code);
      expect(check(flag, joined, url).codes).toContain(code);
    },
  );

  it.each(JOINED)("$flag joined by $sep says nothing on stderr", ({ flag, joined, url }) => {
    const { exit, errLines } = check(flag, joined, url);
    expect(errLines).toEqual([]);
    expect(exit).not.toBe(2);
  });

  it("the whole point, end to end: a two-TLD deny-list joined by a space is not in force", () => {
    const { exit, codes } = check("--deny-tld", "com ru", DOTCOM);
    expect(codes).not.toContain("tld_denied");
    expect(exit).toBe(0);
  });
});

describe("LINK-stuiljry — --deny-port is loud already, with the wrong advice", () => {
  it.each(SEPARATORS)(
    "--deny-port joined by $name is refused as a port-range problem",
    ({ char }) => {
      expect(() =>
        parseCli(["check", "--deny-port", `80${char}8080`, "https://example.com:8080/"]),
      ).toThrow(/invalid --deny-port value: .* \(expected an integer 0-65535\)/s);
    },
  );
});

/**
 * The characters that DO belong in a value. Each of these is a live, matching
 * input today, so none of them may be swept up as a separator: `+` and `-` are
 * in the RFC 3986 scheme grammar (`svn+ssh`, `view-source`), `.` and `-` are in
 * every host and in punycode TLDs (`xn--p1ai`), and a leading/trailing `:` on a
 * scheme is stripped on purpose by the core's `normalizeScheme`.
 */
describe("LINK-stuiljry — characters that legitimately occur inside one value", () => {
  it.each([
    ["--deny-scheme", "svn+ssh", "svn+ssh://h.example.com/", "scheme_denied"],
    ["--deny-scheme", "view-source", "view-source://h.example.com/", "scheme_denied"],
    ["--deny-scheme", "ftp:", FTP, "scheme_denied"],
    ["--deny-scheme", ":ftp", FTP, "scheme_denied"],
    ["--deny-host", "my-corp.com", "https://a.my-corp.com/", "host_denied"],
    ["--deny-host", ".evil.com", EVIL, "host_denied"],
    ["--deny-tld", ".com", DOTCOM, "tld_denied"],
    ["--deny-tld", "xn--p1ai", "https://a.example.xn--p1ai/", "tld_denied"],
  ])("%s %s still matches and reports %s", (flag, value, url, code) => {
    expect(check(flag, value, url).codes).toContain(code as string);
  });
});

/**
 * Padding is NOT a separator. LINK-uxkrtcnw deliberately made a surrounding
 * space harmless by trimming at the core's `normalizedList` choke point, so
 * `--deny-tld " com"` matches. Any screen for whitespace has to leave that
 * alone, which is why these cases are pinned next to the joined ones.
 *
 * `--idn-allow` is absent on purpose: `idnAllowlist` is normalized in
 * `normalizeOptions` without routing through `normalizedList`, so it does not
 * inherit that trim.
 */
describe("LINK-stuiljry — surrounding whitespace on a single value still matches", () => {
  it.each([
    ["--deny-tld", " com", DOTCOM, "tld_denied"],
    ["--deny-tld", "com ", DOTCOM, "tld_denied"],
    ["--deny-tld", "\tcom\n", DOTCOM, "tld_denied"],
    ["--deny-host", " evil.com ", EVIL, "host_denied"],
    ["--deny-scheme", "\tftp ", FTP, "scheme_denied"],
  ])("%s %j matches and reports %s", (flag, value, url, code) => {
    expect(check(flag, value, url).codes).toContain(code as string);
  });

  it.each([
    ["--allow-tld", " com ", DOTCOM, "tld_not_allowlisted"],
    ["--allow-host", " evil.com ", EVIL, "host_not_allowlisted"],
    ["--allow-scheme", "\tftp\n", FTP, "scheme_denied"],
  ])("%s %j allow-lists the value and clears %s", (flag, value, url, code) => {
    expect(check(flag, value, url).codes).not.toContain(code as string);
  });
});
