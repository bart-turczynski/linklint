import { describe, expect, it } from "vitest";
import { parseCli, UsageError } from "@linklint/cli";

describe("parseCli — dispatch", () => {
  it("dispatches check with explicit URLs (stdin false)", () => {
    const cli = parseCli(["check", "https://a.example", "https://b.example"]);
    expect(cli.kind).toBe("check");
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.urls).toEqual(["https://a.example", "https://b.example"]);
    expect(cli.stdin).toBe(false);
  });

  it("dispatches batch with a file argument", () => {
    const cli = parseCli(["batch", "urls.txt"]);
    expect(cli.kind).toBe("batch");
    if (cli.kind !== "batch") throw new Error("unreachable");
    expect(cli.file).toBe("urls.txt");
  });

  it("check with no URLs sets stdin true and empty urls", () => {
    const cli = parseCli(["check"]);
    expect(cli.kind).toBe("check");
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.stdin).toBe(true);
    expect(cli.urls).toEqual([]);
  });

  it("check with single `-` sets stdin true", () => {
    const cli = parseCli(["check", "-"]);
    expect(cli.kind).toBe("check");
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.stdin).toBe(true);
    expect(cli.urls).toEqual([]);
  });
});

describe("parseCli — flags resolve onto options", () => {
  it("resolves all boolean and string flags", () => {
    const cli = parseCli([
      "check",
      "--json",
      "--offline",
      "--fail-on",
      "medium",
      "--allow-invalid",
      "--quiet",
      "--no-color",
      "--allow-idn",
      "--idn-allow",
      "münchen.de",
      "--idn-allow",
      "köln.de",
      "--deny-tld",
      "tk",
      "--deny-tld",
      "zip",
      "--allow-tld",
      "com",
      "--deny-host",
      "evil.com",
      "--allow-host",
      "mycompany.com",
      "--allow-scheme",
      "https",
      "--deny-scheme",
      "javascript",
      "--deny-port",
      "8080",
      "--deny-port",
      "31337",
      "--deny-non-standard-ports",
      "https://x.example",
    ]);
    expect(cli.kind).toBe("check");
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options).toEqual({
      json: true,
      offline: true,
      failOn: "medium",
      allowInvalid: true,
      quiet: true,
      noColor: true,
      agent: false,
      allowIdn: true,
      idnAllowlist: ["münchen.de", "köln.de"],
      denyTlds: ["tk", "zip"],
      allowTlds: ["com"],
      denyHosts: ["evil.com"],
      allowHosts: ["mycompany.com"],
      allowSchemes: ["https"],
      denySchemes: ["javascript"],
      denyPorts: [8080, 31337],
      denyNonStandardPorts: true,
    });
  });

  it("defaults failOn to high and all booleans false", () => {
    const cli = parseCli(["check", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options).toEqual({
      json: false,
      offline: false,
      failOn: "high",
      allowInvalid: false,
      quiet: false,
      noColor: false,
      agent: false,
      allowIdn: false,
      idnAllowlist: [],
      denyTlds: [],
      allowTlds: [],
      denyHosts: [],
      allowHosts: [],
      allowSchemes: [],
      denySchemes: [],
      denyPorts: [],
      denyNonStandardPorts: false,
    });
  });
});

describe("parseCli — short-circuits", () => {
  it("--help short-circuits any subcommand", () => {
    expect(parseCli(["--help"]).kind).toBe("help");
    expect(parseCli(["check", "--help", "https://x.example"]).kind).toBe("help");
  });

  it("--version short-circuits any subcommand", () => {
    expect(parseCli(["--version"]).kind).toBe("version");
    expect(parseCli(["check", "--version", "https://x.example"]).kind).toBe("version");
  });
});

describe("parseCli — usage errors", () => {
  it("throws UsageError on bad --fail-on", () => {
    expect(() => parseCli(["check", "--fail-on", "bogus", "https://x.example"])).toThrow(
      UsageError,
    );
  });

  it("throws UsageError on unknown command", () => {
    expect(() => parseCli(["frobnicate", "https://x.example"])).toThrow(UsageError);
  });

  it("throws UsageError on unknown flag", () => {
    expect(() => parseCli(["check", "--bogus", "https://x.example"])).toThrow(UsageError);
  });

  it("throws UsageError on missing command", () => {
    expect(() => parseCli([])).toThrow(UsageError);
  });

  it("throws UsageError when batch is missing its file", () => {
    expect(() => parseCli(["batch"])).toThrow(UsageError);
  });

  it("throws UsageError when batch has extra file arguments", () => {
    expect(() => parseCli(["batch", "a.txt", "b.txt"])).toThrow(UsageError);
  });
});

// LINK-brsntven. `risky_tld` was deleted because curated TLD membership is a
// fact about the world, and §1.1's answer is that the caller supplies that
// judgment. That answer was false in practice for the CLI, which shipped ZERO
// policy flags: a `linklint check` user lost the signal with no lever at all.
// These two flags are the lever, and they emit the weight-0 policy codes rather
// than re-creating a scoring finding.
describe("parseCli — the caller-owned TLD judgment (LINK-brsntven)", () => {
  it("--deny-tld is repeatable and lands on denyTlds", () => {
    const cli = parseCli(["check", "--deny-tld", "tk", "--deny-tld", "ml", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyTlds).toEqual(["tk", "ml"]);
    expect(cli.options.allowTlds).toEqual([]);
  });

  it("--allow-tld is repeatable and lands on allowTlds", () => {
    const cli = parseCli(["check", "--allow-tld", "com", "--allow-tld", "de", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.allowTlds).toEqual(["com", "de"]);
    expect(cli.options.denyTlds).toEqual([]);
  });

  it("both may be set together — the two lists fire independently", () => {
    const cli = parseCli(["check", "--deny-tld", "tk", "--allow-tld", "com", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyTlds).toEqual(["tk"]);
    expect(cli.options.allowTlds).toEqual(["com"]);
  });

  it("a bare --deny-tld with no value is a usage error", () => {
    expect(() => parseCli(["check", "--deny-tld"])).toThrow(UsageError);
  });
});

// LINK-okvdbkbk. The TLD pair above was only half the remedy: the same argument
// covers the host, scheme and port axes, which the library has always had and
// the CLI did not. Behavioral coverage lives in `policy-flags.test.ts`; these
// pin the parse layer — every value flag repeatable, every bare flag a usage
// error, and the two non-string-list axes not forced into the string shape.
describe("parseCli — the remaining policy axes (LINK-okvdbkbk)", () => {
  it.each([
    ["--deny-host", "denyHosts"],
    ["--allow-host", "allowHosts"],
    ["--allow-scheme", "allowSchemes"],
    ["--deny-scheme", "denySchemes"],
  ] as const)("%s is repeatable and lands on %s", (flag, key) => {
    const cli = parseCli(["check", flag, "a", flag, "b", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options[key]).toEqual(["a", "b"]);
  });

  it("--deny-port is repeatable and lands on denyPorts as numbers, not strings", () => {
    const cli = parseCli(["check", "--deny-port", "8080", "--deny-port", "31337", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyPorts).toEqual([8080, 31337]);
  });

  it("--deny-non-standard-ports is a boolean, taking no value", () => {
    const cli = parseCli(["check", "--deny-non-standard-ports", "https://x.example"]);
    if (cli.kind !== "check") throw new Error("unreachable");
    expect(cli.options.denyNonStandardPorts).toBe(true);
    // The positional survives: the flag did not swallow it as its value.
    expect(cli.urls).toEqual(["https://x.example"]);
  });

  it.each(["--deny-host", "--allow-host", "--allow-scheme", "--deny-scheme", "--deny-port"])(
    "a bare %s with no value is a usage error",
    (flag) => {
      expect(() => parseCli(["check", flag])).toThrow(UsageError);
    },
  );

  it("a --deny-port that is not an integer port is a usage error", () => {
    expect(() => parseCli(["check", "--deny-port", "http", "https://x.example"])).toThrow(
      UsageError,
    );
  });
});
