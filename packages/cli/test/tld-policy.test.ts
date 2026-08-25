import { describe, expect, it } from "vitest";
import { inspect, type InspectResult } from "linklint";
import { run } from "@linklint/cli";

/**
 * LINK-brsntven — the caller's TLD lever, end to end.
 *
 * `risky_tld` scored `.tk` at 0.15 from curated list membership alone.
 * Architecture §1.1 says that judgment belongs to the caller, and the library
 * has always exposed it as `denyTlds` / `allowTlds` emitting the weight-0
 * `tld_denied` / `tld_not_allowlisted`. The CLI exposed NOTHING, so for the
 * tool's main surface "the caller supplies the judgment" was not true. These
 * tests pin the lever that makes it true.
 *
 * The point of the weight-0 channel is the part worth asserting: a caller who
 * denies `.tk` gets the annotation and an unchanged deception score, because a
 * policy verdict is not a deception finding.
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

const TK = "https://mycompany.tk/";

function check(...argv: string[]): InspectResult {
  const c = collectors();
  run(["check", "--json", ...argv], c.out, c.err);
  return json(c.outLines);
}

describe("CLI --deny-tld", () => {
  it("emits tld_denied at weight 0 and leaves the score alone", () => {
    const el = check("--deny-tld", "tk", TK);
    const denied = el.reasons.find((r) => r.code === "tld_denied");
    expect(denied).toBeDefined();
    expect(denied?.weight).toBe(0);
    expect(el.score).toBe(0);
    expect(el.severity).toBe("info");
  });

  it("is repeatable, and a non-listed TLD stays quiet", () => {
    expect(check("--deny-tld", "tk", "--deny-tld", "ml", TK).reasons.map((r) => r.code)).toContain(
      "tld_denied",
    );
    expect(
      check("--deny-tld", "ru", "--deny-tld", "cn", TK).reasons.map((r) => r.code),
    ).not.toContain("tld_denied");
  });

  it("is byte-identical to the equivalent library call", () => {
    expect(check("--deny-tld", "tk", TK)).toEqual(inspect(TK, { denyTlds: ["tk"] }));
  });
});

describe("CLI --allow-tld", () => {
  it("emits tld_not_allowlisted for anything off the list, at weight 0", () => {
    const el = check("--allow-tld", "com", TK);
    const off = el.reasons.find((r) => r.code === "tld_not_allowlisted");
    expect(off).toBeDefined();
    expect(off?.weight).toBe(0);
    expect(el.score).toBe(0);
  });

  it("stays quiet for a TLD on the list", () => {
    expect(
      check("--allow-tld", "tk", TK).reasons.map((r) => r.code),
    ).not.toContain("tld_not_allowlisted");
  });

  it("is byte-identical to the equivalent library call", () => {
    expect(check("--allow-tld", "com", TK)).toEqual(inspect(TK, { allowTlds: ["com"] }));
  });
});

describe("the two lists fire independently", () => {
  it("both codes appear when both are configured and both match", () => {
    const codes = check("--deny-tld", "tk", "--allow-tld", "com", TK).reasons.map((r) => r.code);
    expect(codes).toContain("tld_denied");
    expect(codes).toContain("tld_not_allowlisted");
  });
});

describe("no flags means no policy channel at all", () => {
  it("a bare check of the same URL is byte-identical to a default inspect", () => {
    expect(check(TK)).toEqual(inspect(TK));
  });
});
