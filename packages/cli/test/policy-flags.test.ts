import { describe, expect, it } from "vitest";
import { inspect, type InspectOptions, type InspectResult } from "linklint";
import { parseCli, run, UsageError, USAGE } from "@linklint/cli";

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
 * user lost the signal with no lever at all". Two flags were added there and
 * the other six axes, which carry the identical argument, were left behind. So
 * a disposition like LINK-akirjwoq's — a bundled shortener catalog is refused
 * because `denyHosts: ["bit.ly"]` is the caller's own lever — was true of the
 * library and false of the tool's main surface.
 *
 * These tests pin the whole channel reachable from `linklint check`, and pin
 * the property that makes it safe: every one of them is weight 0, so the
 * deception score is identical with and without the flag.
 */

function collectors(): { out: (s: string) => void; err: (s: string) => void; outLines: string[]; errLines: string[] } {
  const outLines: string[] = [];
  const errLines: string[] = [];
  return { out: (s) => outLines.push(s), err: (s) => errLines.push(s), outLines, errLines };
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
const PLAIN = "https://example.com/";

/** One value-taking policy axis: its flag, a firing case, and its library form. */
interface AxisCase {
  /** The CLI flag under test. */
  flag: string;
  /** A value for it that makes the axis fire on `url`. */
  value: string;
  url: string;
  /** The weight-0 policy reason code the axis emits. */
  code: string;
  /** The `inspect()` options the flag must be exactly equivalent to. */
  options: InspectOptions;
}

/**
 * Every value-taking policy axis, with a case that makes it fire. The table is
 * the point of the file: a ninth axis added to `InspectOptions` without a flag
 * has to be added here to be believed, and the shape of a row forces the
 * library/CLI equivalence to be stated. `denyNonStandardPorts` is the one axis
 * that takes no value, so it is asserted alongside rather than in the table.
 */
const AXES: AxisCase[] = [
  { flag: "--deny-tld", value: "tk", url: TK, code: "tld_denied", options: { denyTlds: ["tk"] } },
  {
    flag: "--allow-tld",
    value: "com",
    url: TK,
    code: "tld_not_allowlisted",
    options: { allowTlds: ["com"] },
  },
  {
    flag: "--deny-host",
    value: "evil.com",
    url: EVIL,
    code: "host_denied",
    options: { denyHosts: ["evil.com"] },
  },
  {
    flag: "--allow-host",
    value: "mycompany.com",
    url: EVIL,
    code: "host_not_allowlisted",
    options: { allowHosts: ["mycompany.com"] },
  },
  {
    flag: "--deny-scheme",
    value: "ftp",
    url: FTP,
    code: "scheme_denied",
    options: { denySchemes: ["ftp"] },
  },
  {
    flag: "--allow-scheme",
    value: "https",
    url: FTP,
    code: "scheme_denied",
    options: { allowSchemes: ["https"] },
  },
  {
    flag: "--deny-port",
    value: "8080",
    url: PORTED,
    code: "port_denied",
    options: { denyPorts: [8080] },
  },
];

describe("every policy axis is reachable from `linklint check`", () => {
  it.each(AXES)("$flag emits $code", ({ flag, value, url, code }) => {
    expect(codes(check(flag, value, url))).toContain(code);
  });

  it("--deny-non-standard-ports emits port_denied without enumerating the port", () => {
    expect(codes(check("--deny-non-standard-ports", PORTED))).toContain("port_denied");
  });

  it.each(AXES)("$flag is byte-identical to the equivalent library call", ({ flag, value, url, options }) => {
    expect(check(flag, value, url)).toEqual(inspect(url, options));
  });

  it("--deny-non-standard-ports is byte-identical to the equivalent library call", () => {
    expect(check("--deny-non-standard-ports", PORTED)).toEqual(
      inspect(PORTED, { denyNonStandardPorts: true }),
    );
  });

  it.each(AXES)("$flag appears in --help", ({ flag }) => {
    expect(USAGE).toContain(flag);
  });

  it("--deny-non-standard-ports appears in --help", () => {
    expect(USAGE).toContain("--deny-non-standard-ports");
  });
});

describe("a policy verdict is not a deception finding", () => {
  // The whole reason these are safe to expose on the tool's main surface: the
  // caller's judgment annotates, it never scores. If any of these ever moved a
  // score, the flag would be a scoring knob wearing a policy label.
  it.each(AXES)("$flag leaves score and severity untouched, at weight 0", ({ flag, value, url, code }) => {
    const bare = check(url);
    const withFlag = check(flag, value, url);
    expect(withFlag.reasons.find((r) => r.code === code)?.weight).toBe(0);
    expect(withFlag.score).toBe(bare.score);
    expect(withFlag.severity).toBe(bare.severity);
  });
});

describe("the axes fire independently and are repeatable", () => {
  it("repeated --deny-host entries are all honored", () => {
    expect(codes(check("--deny-host", "other.com", "--deny-host", "evil.com", EVIL))).toContain(
      "host_denied",
    );
    expect(
      codes(check("--deny-host", "other.com", "--deny-host", "third.com", EVIL)),
    ).not.toContain("host_denied");
  });

  it("--deny-host matches at registrable-domain granularity, covering subdomains", () => {
    expect(codes(check("--deny-host", "evil.com", EVIL))).toContain("host_denied");
  });

  it("several axes combine in one invocation", () => {
    const found = codes(
      check(
        "--deny-tld",
        "com",
        "--deny-host",
        "example.com",
        "--allow-scheme",
        "http",
        "--deny-port",
        "8080",
        PORTED,
      ),
    );
    expect(found).toContain("tld_denied");
    expect(found).toContain("host_denied");
    expect(found).toContain("scheme_denied");
    expect(found).toContain("port_denied");
  });
});

describe("the port axes only look at an explicit port", () => {
  it("a URL with no port never emits port_denied", () => {
    expect(codes(check("--deny-port", "443", PLAIN))).not.toContain("port_denied");
    expect(codes(check("--deny-non-standard-ports", PLAIN))).not.toContain("port_denied");
  });

  it("a standard port is standard", () => {
    expect(
      codes(check("--deny-non-standard-ports", "https://example.com:443/")),
    ).not.toContain("port_denied");
  });
});

describe("a bad --deny-port is a usage error, not a silently dead policy", () => {
  // The core's `normalizePort` keeps any `number` it is handed, so a coerced
  // NaN/float/negative would become a deny-list entry no parsed URL can equal:
  // a policy the caller believes is in force and silently is not.
  //
  // `" 80"` was in this list and is not a member of the class. It is a valid
  // port with padding, and padding is harmless on every other repeatable value
  // flag because the core trims at `normalizedList`; it was refused here only
  // because `parsePort` ran before that trim could reach the value. Fixed and
  // pinned in `policy-value-separators.test.ts` (LINK-patktxpv). Note `"+80"`
  // and `""` stay in: `+` is not padding, and an all-whitespace value trims to
  // empty, which is no port at all.
  it.each(["", "http", "8080abc", "80.5", "-1", "65536", "0x1f90", "1e3", "+80", "   "])(
    "--deny-port %j throws UsageError",
    (value) => {
      expect(() => parseCli(["check", "--deny-port", value, PLAIN])).toThrow(UsageError);
    },
  );

  it("padding is not in that class — a padded valid port is the port", () => {
    const cli = parseCli(["check", "--deny-port", " 80 ", PLAIN]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyPorts).toEqual([80]);
  });

  it("names the offending value and the accepted range", () => {
    expect(() => parseCli(["check", "--deny-port", "99999", PLAIN])).toThrow(/99999.*0-65535/s);
  });

  it("exits 2 and prints usage rather than inspecting anything", () => {
    const c = collectors();
    expect(run(["check", "--deny-port", "nope", PLAIN], c.out, c.err)).toBe(2);
    expect(c.outLines).toEqual([]);
    expect(c.errLines.join("\n")).toContain("invalid --deny-port value");
  });

  it("accepts the edges of the valid range", () => {
    const cli = parseCli(["check", "--deny-port", "0", "--deny-port", "65535", PLAIN]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyPorts).toEqual([0, 65535]);
  });
});

describe("no policy flag means no policy channel at all", () => {
  it("a bare check is byte-identical to a default inspect", () => {
    expect(check(TK)).toEqual(inspect(TK));
    expect(check(TK).checksRun).not.toContain("policy");
  });

  it("an unset axis contributes nothing, even alongside a set one", () => {
    // Presence of a key — even an empty list — is what makes the core report a
    // policy channel, so the CLI must omit keys the caller never set.
    expect(check("--deny-tld", "tk", TK)).toEqual(inspect(TK, { denyTlds: ["tk"] }));
  });
});
