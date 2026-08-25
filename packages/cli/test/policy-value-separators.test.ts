import { describe, expect, it } from "vitest";
import type { InspectResult } from "linklint";
import { parseCli, run, UsageError } from "@linklint/cli";

/**
 * LINK-stuiljry — the residual of LINK-ynozvajn: a policy value joined by
 * anything OTHER than a comma.
 *
 * LINK-ynozvajn scoped itself to the comma and said so. Every other joining
 * character a caller might reach for was still handed to `parseArgs` as ONE
 * value, matched nothing on any axis, and was reported nowhere:
 *
 *     linklint check --deny-tld "com ru" https://a.example.com/   ->  exit 0
 *
 * The first commit on this branch pinned exactly that, so this one had a
 * behavior to invert rather than a description to write. Both failure shapes
 * were the comma's:
 *
 *   - on a DENY axis the list was void: the reason the repeated form produces
 *     did not appear, and nothing said so;
 *   - on an ALLOW axis it was worse than void: the joined string matched
 *     nothing, so a value the caller explicitly listed came back reported as
 *     NOT allow-listed — and `--idn-allow` behaves as an allow axis here, its
 *     exemption silently failing to apply.
 *
 * `--deny-port` was the one axis already loud for every separator, because
 * `parsePort` admits only digits — loud, but answering a question about
 * separators with advice about the port range. It is screened first now, so it
 * answers the question that was asked.
 *
 * THE SET IS `,` `;` `|` AND WHITESPACE, and the reasoning for each character
 * is in `assertNotJoined` in `packages/cli/src/args.ts`. The control blocks at
 * the bottom are the load-bearing half: they fix the characters that DO
 * legitimately appear in a matching value today (`+ - . :`) and the padded
 * single value LINK-uxkrtcnw made harmless, so the refusal cannot quietly eat
 * either one.
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
/** The one URL with an explicit port, so `--deny-port` has something to match. */
const PORTED = "https://example.com:8080/";

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
const SEPARATORS: ReadonlyArray<{ name: string; char: string; named: string }> = [
  { name: "space", char: " ", named: "space" },
  { name: "tab", char: "\t", named: "tab" },
  { name: "newline", char: "\n", named: "newline" },
  { name: "no-break space", char: "\u00a0", named: "whitespace character" },
  { name: "semicolon", char: ";", named: "semicolon" },
  { name: "vertical bar", char: "|", named: "vertical bar" },
];

/** Every (axis, separator) pair, flattened so each is its own named case. */
const JOINED = AXES.flatMap((axis) =>
  SEPARATORS.map((sep) => ({
    ...axis,
    sep: sep.name,
    named: sep.named,
    joined: axis.values.join(sep.char),
  })),
);

describe("LINK-stuiljry — a joined value is refused, not silently voided", () => {
  it.each(JOINED)("$flag joined by $sep throws UsageError", ({ flag, joined, url }) => {
    expect(() => parseCli(["check", flag, joined, url])).toThrow(UsageError);
  });

  it.each(JOINED)(
    "$flag joined by $sep names the character and the repeatable form",
    ({ flag, joined, values, url, named }) => {
      expect(() => parseCli(["check", flag, joined, url])).toThrow(
        `invalid ${flag} value: ${joined} (a ${named} is not a value separator — repeat the flag once per value: ${flag} ${values[0]} ${flag} ${values[1]})`,
      );
    },
  );

  it.each(JOINED)("$flag joined by $sep exits 2 and inspects nothing", ({ flag, joined, url }) => {
    const c = collectors();
    expect(run(["check", "--json", flag, joined, url], c.out, c.err)).toBe(2);
    expect(c.outLines).toEqual([]);
    expect(c.errLines.join("\n")).toContain("is not a value separator");
  });

  it.each(AXES)(
    "$flag repeated is untouched and still decides $code",
    ({ flag, values, url, code, fires }) => {
      const { codes } = check(flag, values[0], flag, values[1], url);
      expect(codes.includes(code)).toBe(fires);
    },
  );

  it("the whole point, end to end: a two-TLD deny-list joined by a space is refused", () => {
    const c = collectors();
    expect(run(["check", "--json", "--deny-tld", "com ru", DOTCOM], c.out, c.err)).toBe(2);
    expect(c.errLines.join("\n")).toContain(
      "invalid --deny-tld value: com ru (a space is not a value separator",
    );
  });

  it("one separator anywhere in the value is enough, not just between two items", () => {
    expect(() => parseCli(["check", "--deny-tld", "com;", DOTCOM])).toThrow(UsageError);
    expect(() => parseCli(["check", "--deny-tld", "|com", DOTCOM])).toThrow(UsageError);
    expect(() => parseCli(["check", "--deny-host", "a.example|b.example", DOTCOM])).toThrow(
      UsageError,
    );
  });

  it("the character named is the first one found, when a value holds several", () => {
    expect(() => parseCli(["check", "--deny-tld", "com; ru", DOTCOM])).toThrow(
      "a semicolon is not a value separator — repeat the flag once per value: --deny-tld com --deny-tld ru",
    );
    expect(() => parseCli(["check", "--deny-tld", "com ;ru", DOTCOM])).toThrow(
      "a space is not a value separator — repeat the flag once per value: --deny-tld com --deny-tld ru",
    );
  });

  it("an exotic whitespace character is refused without being misnamed", () => {
    expect(() => parseCli(["check", "--deny-tld", "com\u00a0ru", DOTCOM])).toThrow(
      "a whitespace character is not a value separator",
    );
  });

  it("a value that is nothing but separators still gets advice, without an empty example", () => {
    expect(() => parseCli(["check", "--deny-tld", ";|;", DOTCOM])).toThrow(
      "invalid --deny-tld value: ;|; (a semicolon is not a value separator — repeat --deny-tld once per value)",
    );
  });

  it("a long joined list elides the suggestion rather than restating all of it", () => {
    expect(() => parseCli(["check", "--deny-tld", "a b c d e", DOTCOM])).toThrow(
      "repeat the flag once per value: --deny-tld a --deny-tld b --deny-tld c ...",
    );
  });

  it("only the list flags are screened — a separator elsewhere is not this error", () => {
    // LINK-ynozvajn pinned this for the comma and it holds for the wider set:
    // `--fail-on` takes one value from a closed set and reports its own problem,
    // and a URL positional legitimately holds any of these characters.
    expect(() => parseCli(["check", "--fail-on", "high low", DOTCOM])).toThrow(/invalid --fail-on/);
    const cli = parseCli(["check", "https://example.com/a;b?x=1|2"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.urls).toEqual(["https://example.com/a;b?x=1|2"]);
  });
});

describe("LINK-stuiljry — --deny-port is told about separators, not about its range", () => {
  it.each(SEPARATORS)("--deny-port joined by $name reports the separator", ({ char, named }) => {
    expect(() => parseCli(["check", "--deny-port", `80${char}8080`, PORTED])).toThrow(
      `(a ${named} is not a value separator`,
    );
  });

  it("--deny-port still reports its range problem when there is no separator", () => {
    expect(() => parseCli(["check", "--deny-port", "99999", DOTCOM])).toThrow(
      /invalid --deny-port value: 99999 \(expected an integer 0-65535\)/,
    );
  });
});

/**
 * LINK-patktxpv — padding on `--deny-port`, PINNED AS IT BEHAVES TODAY.
 *
 * This block is written before the fix, so it describes the defect rather than
 * the intent: `--deny-port " 8080 "` is a usage error while the same padding on
 * every other repeatable value flag is harmless. The cause is ordering, not
 * judgment — `parsePort` runs on the raw argv string and its `/^\d{1,5}$/` sees
 * the padding, so the core's `normalizedList` trim never gets the chance.
 *
 * It is LOUD, not a fail-open: exit 2 and a message. That is the opposite of
 * the `idnAllowlist` and `suppressReasons` defects, which were silent. What
 * makes it worth inverting is that two prose sites assert the tolerant behavior
 * over a block that lists this flag (`packages/cli/src/cli.ts` help text,
 * `packages/cli/README.md`), and both are false today for this one flag.
 *
 * The rest of the block is CONTROLS, and they must read identically after the
 * inversion. Trimming padding must not weaken the separator screen: `trim` and
 * `\s` are the same set in the language, which is exactly why LINK-stuiljry
 * could call the screen "the padding trimming cannot reach because it is in the
 * middle". These cases are what turns that from an argument into a measurement.
 */

/** Every separator, joining two ports that are each valid alone. */
const PORT_JOINED: ReadonlyArray<readonly [string, string]> = [
  ["80 443", "a space"],
  ["80,443", "a comma"],
  ["80;443", "a semicolon"],
  ["80|443", "a vertical bar"],
];

describe("LINK-patktxpv — padding on --deny-port, pinned before the fix", () => {
  it("DEFECT: a padded port value is refused, unlike the same padding elsewhere", () => {
    expect(() => parseCli(["check", "--deny-port", " 8080 ", PORTED])).toThrow(
      "invalid --deny-port value:  8080  (expected an integer 0-65535)",
    );
    // The control that makes it a defect rather than a policy: identical
    // padding on a sibling flag matches, because `denyTlds` reaches the core's
    // trim as a string and `denyPorts` does not.
    expect(check("--deny-tld", " com ", DOTCOM).codes).toContain("tld_denied");
  });

  it("DEFECT: end to end it is loud — exit 2, nothing inspected, no silent void", () => {
    const c = collectors();
    expect(run(["check", "--json", "--deny-port", " 8080 ", PORTED], c.out, c.err)).toBe(2);
    expect(c.outLines).toEqual([]);
    expect(c.errLines.join("\n")).toContain("expected an integer 0-65535");
  });

  it("GAP: the derived padded-value guard does not reach --deny-port today", () => {
    // `AXES` is the guard's domain, and it excludes the port flag. Nothing
    // fails while the padded case above is missing, which is why the defect
    // could sit here unpinned next to seven flags that are pinned.
    expect(AXES.map((axis) => axis.flag)).not.toContain("--deny-port");
  });

  it.each(PORT_JOINED)(
    "CONTROL: --deny-port %j stays refused as %s, with the repeatable-form remedy",
    (joined, named) => {
      expect(() => parseCli(["check", "--deny-port", joined, PORTED])).toThrow(
        `invalid --deny-port value: ${joined} (${named} is not a value separator — ` +
          "repeat the flag once per value: --deny-port 80 --deny-port 443)",
      );
    },
  );

  it("CONTROL: padding AROUND an interior separator does not launder it", () => {
    // The case that would break if a fix trimmed and then screened the trimmed
    // value only to hand the RAW one on, or trimmed hard enough to reach inside.
    expect(() => parseCli(["check", "--deny-port", " 80 443 ", PORTED])).toThrow(
      "invalid --deny-port value:  80 443  (a space is not a value separator — " +
        "repeat the flag once per value: --deny-port 80 --deny-port 443)",
    );
  });

  it("CONTROL: a padded value that is out of range still gets the range advice", () => {
    expect(() => parseCli(["check", "--deny-port", " 99999 ", PORTED])).toThrow(
      "invalid --deny-port value:  99999  (expected an integer 0-65535)",
    );
  });

  it("CONTROL: a padded value that is not a number at all still gets the range advice", () => {
    expect(() => parseCli(["check", "--deny-port", " nope ", PORTED])).toThrow(
      "invalid --deny-port value:  nope  (expected an integer 0-65535)",
    );
  });
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
 * `--idn-allow` belongs in the tables, and its absence was the tell. It was
 * excluded here on the premise that `idnAllowlist` is normalized in
 * `normalizeOptions` without routing through `normalizedList`, and so does not
 * inherit that trim. MR !56 (LINK-qajalduf) retired that premise: `idnAllowlist`
 * routes through the choke point now, a padded value exempts exactly as an
 * unpadded one does, and the exclusion had quietly become a coverage gap rather
 * than a decision (LINK-bsudgkfk).
 *
 * Trimming is a property of every LIST-VALUED caller option, not of the policy
 * axes — reading it as axis-scoped is what shipped two fail-opens. Which options
 * are in the class, which route through `normalizedList`, and why the ones that
 * cannot are named rather than counted, are all DERIVED from the source by
 * `packages/core/test/list-option-trim-scope.test.ts`; this file does not
 * restate them.
 */
/** A padded value whose axis reason must still FIRE. */
const PADDED_FIRES: ReadonlyArray<readonly [string, string, string, string]> = [
  ["--deny-tld", " com", DOTCOM, "tld_denied"],
  ["--deny-tld", "com ", DOTCOM, "tld_denied"],
  ["--deny-tld", "\tcom\n", DOTCOM, "tld_denied"],
  ["--deny-host", " evil.com ", EVIL, "host_denied"],
  ["--deny-scheme", "\tftp ", FTP, "scheme_denied"],
];

/** A padded value whose axis reason must still be CLEARED. */
const PADDED_CLEARS: ReadonlyArray<readonly [string, string, string, string]> = [
  ["--allow-tld", " com ", DOTCOM, "tld_not_allowlisted"],
  ["--allow-host", " evil.com ", EVIL, "host_not_allowlisted"],
  ["--allow-scheme", "\tftp\n", FTP, "scheme_denied"],
  ["--idn-allow", " münchen.de ", MUNICH, "idn_host"],
  ["--idn-allow", "\tmünchen.de\n", MUNICH, "idn_host"],
];

describe("LINK-stuiljry — surrounding whitespace on a single value still matches", () => {
  // The case titles name the URL as well as the code: with four columns and
  // three placeholders the trailing `%s` used to consume the URL and print it
  // where the reader expected the reason code.
  it.each(PADDED_FIRES)("%s %j on %s matches and reports %s", (flag, value, url, code) => {
    expect(check(flag, value, url).codes).toContain(code);
  });

  it.each(PADDED_CLEARS)(
    "%s %j on %s allow-lists the value and clears %s",
    (flag, value, url, code) => {
      expect(check(flag, value, url).codes).not.toContain(code);
    },
  );

  // LINK-bsudgkfk. The exclusion this block once carried was silent: nothing
  // failed when `--idn-allow` sat outside the padded tables, so the coverage
  // gap outlived the premise it rested on. Derive the requirement instead —
  // every string-valued repeatable flag the file already enumerates in `AXES`
  // has to appear in one of the two tables above, so a new axis added there
  // reddens here rather than waiting for a reader to notice.
  it("pins a padded value for every string-valued repeatable flag", () => {
    const padded = new Set([...PADDED_FIRES, ...PADDED_CLEARS].map(([flag]) => flag));
    for (const { flag } of AXES) {
      expect(
        padded.has(flag),
        `${flag} has no padded-value case. A padded single value is harmless on ` +
          "every flag whose option routes through the core's `normalizedList` " +
          "choke point (LINK-uxkrtcnw, LINK-qajalduf); add a row to " +
          "PADDED_FIRES or PADDED_CLEARS rather than excluding the flag.",
      ).toBe(true);
    }
  });
});
