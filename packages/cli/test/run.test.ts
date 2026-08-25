import { describe, expect, it } from "vitest";
import { inspect, type InspectResult } from "linklint";
import { run } from "@linklint/cli";

/** Collect output lines from a `run` invocation. */
function collectors(): { out: (s: string) => void; err: (s: string) => void; outLines: string[]; errLines: string[] } {
  const outLines: string[] = [];
  const errLines: string[] = [];
  return {
    out: (s) => outLines.push(s),
    err: (s) => errLines.push(s),
    outLines,
    errLines,
  };
}

const BENIGN = "https://www.example.com/path";
// LINK-brsntven note: the previous `high` fixture was
// `https://www.gооgle.com@bad.tk/login`, which reached 0.575/high only because
// `risky_tld` added 0.15 on top of `userinfo_present` — the Cyrillic homoglyphs
// sit in the USERINFO, not the host, so nothing else fired. With `risky_tld`
// deleted it reads 0.500/medium and stopped exercising the `high` band. The
// replacement is a deep-subdomain phish that reaches `high` from two structural
// findings and no membership lookup.
const HIGH = "https://a.b.c.d.paypal.com.evil-login.tk/";
const INVALID = "ht!tp://%%%not a url";

describe("run — exit-code matrix (explicit URL args, never reads stdin)", () => {
  it("benign URL => 0", () => {
    const c = collectors();
    expect(run(["check", BENIGN, "--no-color"], c.out, c.err)).toBe(0);
  });

  it("high-risk URL => 1", () => {
    const c = collectors();
    expect(run(["check", HIGH, "--no-color"], c.out, c.err)).toBe(1);
  });

  it("invalid URL => 1", () => {
    const c = collectors();
    expect(run(["check", INVALID, "--no-color"], c.out, c.err)).toBe(1);
  });

  it("invalid URL + --allow-invalid => 0", () => {
    const c = collectors();
    expect(run(["check", INVALID, "--allow-invalid", "--no-color"], c.out, c.err)).toBe(0);
  });

  it("usage error (unknown flag) => 2 and writes USAGE to err", () => {
    const c = collectors();
    expect(run(["check", "--bogus", BENIGN], c.out, c.err)).toBe(2);
    expect(c.errLines.join("\n")).toContain("Usage:");
  });

  it("usage error (bad --fail-on) => 2", () => {
    const c = collectors();
    expect(run(["check", "--fail-on", "nope", BENIGN], c.out, c.err)).toBe(2);
  });

  it("--help => 0 and prints USAGE to out", () => {
    const c = collectors();
    expect(run(["--help"], c.out, c.err)).toBe(0);
    expect(c.outLines.join("\n")).toContain("Usage:");
  });

  it("--version => 0 and prints a version to out", () => {
    const c = collectors();
    expect(run(["--version"], c.out, c.err)).toBe(0);
    expect(c.outLines.join("\n").trim().length).toBeGreaterThan(0);
  });
});

describe("run — JSON-shape parity with core InspectResult", () => {
  it("--json output parses to an array with the core schema fields", () => {
    const c = collectors();
    const code = run(["check", "--json", BENIGN], c.out, c.err);
    expect(code).toBe(0);
    const parsed = JSON.parse(c.outLines.join("\n")) as InspectResult[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(1);

    const el = parsed[0];
    expect(el).toBeDefined();
    if (!el) throw new Error("unreachable");

    // Parity: the JSON element has the same shape as a direct inspect() call.
    expect(el).toEqual(inspect(BENIGN));

    // Spot-check the core schema fields are all present.
    for (const key of [
      "schemaVersion",
      "status",
      "score",
      "severity",
      "reasons",
      "confusables",
      "parsed",
      "checksRun",
      "checksSkipped",
      "dataVersions",
    ] as const) {
      expect(el).toHaveProperty(key);
    }
  });

  it("--json emits one element per URL", () => {
    const c = collectors();
    run(["check", "--json", BENIGN, HIGH], c.out, c.err);
    const parsed = JSON.parse(c.outLines.join("\n")) as InspectResult[];
    expect(parsed).toHaveLength(2);
  });
});
