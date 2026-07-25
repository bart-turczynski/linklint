import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CONFUSABLES, CONFUSABLES_VERSION } from "../src/data/confusables.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { inspect } from "../src/index.js";

/**
 * LINK-hfencvmf — drift guard for the generated UTS#39 confusables table.
 *
 * `build-confusables.mjs` always had a `--check` mode, but its default input was
 * a NETWORK FETCH, so nothing could run it in CI and
 * `src/data/confusables.generated.ts` could drift from its source unnoticed —
 * the one generated artifact without a guard. S3 fixed the same gap for the IANA
 * ranges (`ip-ranges.test.ts`); this closes it here, the same way: commit the
 * parsed snapshot under `tools/data/`, make the default mode offline, and run
 * `--check` from the suite.
 *
 * Note this guards the artifact against its INPUT, at whatever version is
 * pinned. Whether to move that pin (Unicode 16.0.0 → 17.0, to match the tr46
 * baseline established by U1) is a separate, verdict-affecting decision.
 */

// Resolved relative to THIS module so the test runs from any working directory.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const GENERATOR = join(REPO_ROOT, "tools", "build-confusables.mjs");
const SNAPSHOT = join(REPO_ROOT, "tools", "data", "confusables.txt");
const ARTIFACT = join(REPO_ROOT, "packages", "core", "src", "data", "confusables.generated.ts");

describe("confusables.generated.ts is reproducible from the committed snapshot", () => {
  it("--check passes: re-parsing the snapshot reproduces the artifact", () => {
    expect(() =>
      execFileSync(process.execPath, [GENERATOR, "--check"], { stdio: "pipe" }),
    ).not.toThrow();
  });

  it("runs offline — the default mode reads the snapshot, never the network", () => {
    // If the default path still fetched, this would be the test that hangs or
    // flakes in an air-gapped CI. Asserting the file exists and is the parsed
    // input keeps the offline guarantee explicit.
    expect(statSync(SNAPSHOT).size).toBeGreaterThan(500_000);
    const source = readFileSync(SNAPSHOT, "utf8");
    expect(source).toContain("confusables.txt");
    expect(source).toContain("Unicode Security Mechanisms");
  });

  it("the sha256 recorded in the artifact is the digest of the committed snapshot", () => {
    // The strongest link in the chain: the artifact names the exact bytes it was
    // built from, and those bytes are in the repo. A snapshot swapped without a
    // rebuild fails here even if the parsed OUTPUT happened to be unchanged.
    const digest = createHash("sha256").update(readFileSync(SNAPSHOT)).digest("hex");
    expect(readFileSync(ARTIFACT, "utf8")).toContain(`sha256:  ${digest}`);
  });

  it("is committed byte-for-byte (whitespace hooks are excluded for tools/data/)", () => {
    const bytes = readFileSync(SNAPSHOT);
    expect(bytes.includes("\r".charCodeAt(0))).toBe(false);
    // 4,654 lines carry trailing whitespace upstream; if a hook ever strips them
    // the digest assertion above breaks first, but pin the property directly too.
    expect(/[ \t]+\n/.test(bytes.toString("utf8"))).toBe(true);
  });
});

describe("the generated table is version-stamped and non-empty", () => {
  it("stamps the Unicode version it was curated from", () => {
    expect(DATA_VERSIONS.unicodeConfusables).toBe(CONFUSABLES_VERSION);
    expect(CONFUSABLES_VERSION).toMatch(/^uts39-\d+\.\d+\.\d+-curated$/);
    // Recorded skew: tr46 carries Unicode 17.0 (see idna-conformance.test.ts).
    // These two data sets are pinned independently — see tools/README.md.
    expect(CONFUSABLES_VERSION).toContain("16.0.0");
  });

  it("carries the curated subset, not an empty or truncated parse", () => {
    expect(CONFUSABLES.size).toBeGreaterThan(1000);
    // Spot-check the canonical Cyrillic homograph survives a regeneration.
    expect(CONFUSABLES.get("а")?.target).toBe("a");
  });
});

describe("TRIPWIRE — why the pin is NOT on Unicode 17.0 (LINK-tydjfmci)", () => {
  /**
   * Moving the confusables pin to Unicode 17.0 was measured and **declined**.
   *
   * 17.0 adds `þ → p` (LATIN SMALL LETTER THORN). For a Latin-script host whose
   * only non-ASCII character is `þ`, the whole label then skeletons to pure
   * ASCII, so `homograph_latin_skeleton` — a CRITICAL, weight-1.0 detector —
   * fires on ordinary Icelandic:
   *
   *   þingvellir.is   Unicode 16: info 0.00     Unicode 17: CRITICAL 1.00
   *
   * Þingvellir is a real Icelandic national park and UNESCO World Heritage site.
   * The whole test suite passed under the 17.0 table except the drift guard
   * above — the hand-curated corpus contains no Icelandic, so it confirmed a
   * bump that breaks real browsing. That is precisely the failure mode recorded
   * after `brand_combosquat` (LINK-cqdrdvfu): a curated benign corpus is
   * self-confirming and must never be the evidence for widening a match.
   *
   * These assertions are the tripwire. They pass today and will FAIL on a 17.0
   * bump, next to the `--check` failure that same bump causes — so whoever moves
   * the pin sees the reason, not just a stale artifact. Do not "fix" them by
   * relaxing the expectation: either exclude `þ` from the curated subset, or
   * require a script change before `homograph_latin_skeleton` may fire.
   */
  it.each([
    { host: "þingvellir.is", note: "Icelandic national park; only non-ASCII char is þ" },
    { host: "þjóð.is", note: "Icelandic 'nation'" },
    { host: "þór.is", note: "Icelandic given name" },
  ])("legitimate Icelandic $host stays benign ($note)", ({ host }) => {
    const r = inspect(`https://${host}/`, { idnPolicy: "allow" });
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons.map((x) => x.code)).not.toContain("homograph_latin_skeleton");
  });

  it("THORN is absent from the curated table — the mapping that causes it", () => {
    // Unicode 17.0 maps U+00FE -> "p"; 16.0.0 does not. This single entry is the
    // difference between the rows above scoring 0.00 and 1.00.
    expect(CONFUSABLES.get("þ")).toBeUndefined();
  });

  it("single-script Cyrillic stays benign too (ш -> w is the other 17.0 addition)", () => {
    for (const host of ["школа.рф", "машина.рф", "большой.рф"]) {
      const r = inspect(`https://${host}/`, { idnPolicy: "allow" });
      expect(r.score, host).toBe(0);
      expect(r.reasons.map((x) => x.code), host).not.toContain("homograph_latin_skeleton");
    }
  });
});
