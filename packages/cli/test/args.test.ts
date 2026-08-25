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
