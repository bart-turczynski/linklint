import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import tr46 from "tr46";
import { describe, expect, it } from "vitest";
import { DATA_VERSIONS } from "../src/data/versions.js";
import {
  hasMalformedPunycode,
  toAscii,
  toAsciiUnder,
  toUnicode,
} from "../src/unicode/idna.js";

/**
 * U1 (LINK-cyndxhhw) — the FULL upstream IdnaTestV2 corpus run against
 * linklint's normalization pipeline, not the handful of rows E6 imported.
 *
 * Why a full corpus: every verdict that depends on "what host is this really"
 * flows through `src/unicode/idna.ts`, which is backed by `tr46` (pinned as
 * `dataVersions.idna`). tr46 embeds its own UTS-46 / Unicode data and releases on
 * its own cadence, so a routine bump can silently move a normalization result.
 * Four curated rows will not catch that; 6,391 will.
 *
 * This is NOT `test/corpus/vectors.ts`. That file maps inputs to expected
 * SEVERITY and REASONS; this one tests NORMALIZATION correctness only. Different
 * question, different harness.
 *
 * ── linklint's flag profile ───────────────────────────────────────────────────
 * `idna.ts` passes only `transitionalProcessing`, so every other tr46 option
 * keeps its default of `false`: CheckBidi, CheckHyphens, CheckJoiners,
 * UseSTD3ASCIIRules and VerifyDnsLength are all OFF. That is deliberate —
 * `inspect()` must CLASSIFY hostile input, not reject it, so normalization stays
 * maximally permissive and the detectors decide what is suspicious.
 *
 * The corpus header specifies exactly how to test such an implementation:
 *
 *   "Implementations that allow values of particular input flags to be false
 *    would ignore the corresponding status codes listed in the table below."
 *
 *     VerifyDnsLength: A4_1, A4_2 · CheckHyphens: V2, V3 · CheckJoiners: Cn
 *     CheckBidi: Bn · UseSTD3ASCIIRules: U1
 *
 * IGNORED_STATUS below is that table, transcribed — it is the corpus's own
 * relaxation rule, not a linklint allowlist. Every remaining code (P*, V1, V4,
 * V6, V7, A3) is a hard error linklint must still reproduce.
 *
 * RESULT under that profile: 100.00% on all three operations, zero divergences.
 * The figure is profile-relative — conformance to UTS-46 as linklint configures
 * it, not a claim that linklint admits only strict-IDNA-valid hosts, since a row
 * the corpus fails only through a disabled check counts here as a pass. The shape
 * assertions below keep that number honest — a relaxation that swallowed the
 * corpus would also score a profile-relative 100%, so the error/success split is
 * pinned too.
 */

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CORPUS = join(REPO_ROOT, "packages", "core", "test", "data", "IdnaTestV2.txt");

/** Provenance — see test/data/README.md. */
const PINNED_SHA256 = "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf";
const CORPUS_UNICODE_VERSION = "17.0.0";
const EXPECTED_ROWS = 6391;

/**
 * Status codes tied to a UTS-46 input flag linklint leaves `false`. `X4_2` is the
 * toUnicode counterpart of `A4_2` (the corpus header: it "is now returned where a
 * toASCII error code was formerly being generated in toUnicode due to an empty
 * label"), so it follows VerifyDnsLength off. 271 toUnicode rows depend on it.
 */
const IGNORED_STATUS = /^(A4_1|A4_2|V2|V3|U1|B\d.*|C\d.*|X4_2)$/;

interface Row {
  /** 1-based line number in the corpus, for failure messages. */
  readonly line: number;
  readonly source: string;
  readonly toUnicode: string;
  readonly toUnicodeStatus: readonly string[];
  readonly toAsciiN: string;
  readonly toAsciiNStatus: readonly string[];
  readonly toAsciiT: string;
  readonly toAsciiTStatus: readonly string[];
}

/** `\uXXXX` and `\x{XXXX}` escapes; adjacent pairs re-form astral characters. */
function unescapeCorpus(value: string): string {
  return value
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x\{([0-9A-Fa-f]+)\}/g, (_, h: string) => String.fromCodePoint(parseInt(h, 16)));
}

function parseStatus(field: string): string[] {
  const raw = field.trim();
  if (raw === "" || raw === "[]") return [];
  return raw
    .replace(/^\[|\]$/g, "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

/** Does this row still fail once linklint's disabled-flag codes are removed? */
function expectsError(status: readonly string[]): boolean {
  return status.some((code) => !IGNORED_STATUS.test(code));
}

/**
 * Columns are semicolon-separated; a blank column INHERITS from an earlier one
 * (toAsciiT ← toAsciiN ← toUnicode ← source), and `""` means the empty string.
 */
function parseCorpus(text: string): Row[] {
  const rows: Row[] = [];
  let line = 0;
  for (const physical of text.split("\n")) {
    line++;
    const data = physical.split("#")[0] as string;
    if (data.trim() === "") continue;
    const col = data.split(";").map((c) => c.trim());
    if (col.length < 7) continue;
    const lit = (v: string) => (v === '""' ? "" : unescapeCorpus(v));

    const source = lit(col[0] as string);
    const uni = (col[1] as string) === "" ? source : lit(col[1] as string);
    const uniStatus = parseStatus(col[2] as string);
    const ascN = (col[3] as string) === "" ? uni : lit(col[3] as string);
    const ascNStatus = (col[4] as string) === "" ? uniStatus : parseStatus(col[4] as string);
    const ascT = (col[5] as string) === "" ? ascN : lit(col[5] as string);
    const ascTStatus = (col[6] as string) === "" ? ascNStatus : parseStatus(col[6] as string);

    rows.push({
      line,
      source,
      toUnicode: uni,
      toUnicodeStatus: uniStatus,
      toAsciiN: ascN,
      toAsciiNStatus: ascNStatus,
      toAsciiT: ascT,
      toAsciiTStatus: ascTStatus,
    });
  }
  return rows;
}

const corpusBytes = readFileSync(CORPUS);
const ROWS = parseCorpus(corpusBytes.toString("utf8"));

/**
 * Per the corpus header, an implementation that emits U+FFFD for illegal code
 * points may treat U+FFFD as a wildcard when comparing.
 */
function valueMatches(actual: string | null, expected: string): boolean {
  if (actual === null) return false;
  if (actual === expected) return true;
  if (!actual.includes("�") && !expected.includes("�")) return false;
  if (actual.length !== expected.length) return false;
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i] && actual[i] !== "�" && expected[i] !== "�") {
      return false;
    }
  }
  return true;
}

/** Runs one operation over the whole corpus, returning readable divergences. */
function sweep(
  label: string,
  run: (source: string) => string | null,
  expected: (row: Row) => { value: string; status: readonly string[] },
): string[] {
  const failures: string[] = [];
  for (const row of ROWS) {
    const { value, status } = expected(row);
    const got = run(row.source);
    if (expectsError(status)) {
      if (got !== null) {
        failures.push(
          `${label} L${row.line}: ${JSON.stringify(row.source)} expected ERROR [${status.join(", ")}], got ${JSON.stringify(got)}`,
        );
      }
    } else if (!valueMatches(got, value)) {
      failures.push(
        `${label} L${row.line}: ${JSON.stringify(row.source)} expected ${JSON.stringify(value)}, got ${JSON.stringify(got)}`,
      );
    }
  }
  return failures;
}

describe("IdnaTestV2 corpus provenance", () => {
  it("is the pinned upstream file, byte for byte", () => {
    expect(createHash("sha256").update(corpusBytes).digest("hex")).toBe(PINNED_SHA256);
    // Committed verbatim: .pre-commit-config.yaml excludes test/data/ from the
    // whitespace-rewriting hooks so this digest stays checkable upstream.
    expect(corpusBytes.includes("\r".charCodeAt(0))).toBe(false);
  });

  it("declares the Unicode version this suite was triaged against", () => {
    const header = corpusBytes.toString("utf8").slice(0, 400);
    expect(header).toContain("# IdnaTestV2.txt");
    expect(header).toContain(`# Version: ${CORPUS_UNICODE_VERSION}`);
  });

  it("parses to the expected row count and column semantics", () => {
    expect(ROWS).toHaveLength(EXPECTED_ROWS);
    // Landmark rows prove escape decoding and blank-column inheritance work; a
    // parser bug that silently dropped columns would otherwise read as conformance.
    const at = (source: string) => ROWS.find((r) => r.source === source);
    expect(at("faß.de")).toMatchObject({ toAsciiN: "xn--fa-hia.de", toAsciiT: "fass.de" });
    expect(at("Faß.de")).toMatchObject({ toUnicode: "faß.de", toAsciiT: "fass.de" });
    expect(at("xn--fa-hia.de")?.toUnicode).toBe("faß.de");
    // HEBREW ALEF decoded from `א`, and toAsciiNStatus inherited [B5, B6]
    // from toUnicodeStatus. Escapes here rather than literals: this file must not
    // itself contain the invisible characters it is asserting about.
    expect(at("\u00E0\u05D0")).toMatchObject({
      toAsciiN: "xn--0ca24w",
      toAsciiNStatus: ["B5", "B6"],
    });
    expect(at("\u200D")?.toAsciiN).toBe("xn--1ug"); // ZERO WIDTH JOINER
  });
});

describe("corpus shape — keeps the profile-relative 100% figure honest", () => {
  // A relaxation rule that forgave everything would also report a profile-relative
  // 100%. Pinning the split proves both channels are exercised: 4,181 rows must
  // still FAIL under linklint's profile, and 2,210 must SUCCEED.
  const errorRows = ROWS.filter((r) => expectsError(r.toAsciiNStatus));
  const okRows = ROWS.filter((r) => !expectsError(r.toAsciiNStatus));

  it("exercises both the error and the success channel", () => {
    expect(errorRows).toHaveLength(4181);
    expect(okRows).toHaveLength(2210);
    expect(errorRows.length + okRows.length).toBe(EXPECTED_ROWS);
  });

  it("the flag relaxation is load-bearing, not decorative", () => {
    // Rows the corpus calls an error that linklint accepts *only* because a flag
    // is off. Without the documented relaxation these 1,661 would be divergences.
    const relaxed = okRows.filter((r) => r.toAsciiNStatus.length > 0);
    expect(relaxed).toHaveLength(1661);
  });

  it("covers the character classes that actually matter to detectors", () => {
    expect(ROWS.filter((r) => /[^\u0000-\u007F]/.test(r.source))).toHaveLength(4043);
    expect(ROWS.filter((r) => /(^|\.)xn--/i.test(r.source))).toHaveLength(2384);
  });
});

describe("UTS-46 conformance under linklint's documented flag profile", () => {
  it("toASCII nontransitional (IDNA2008): 6391/6391", () => {
    const failures = sweep(
      "toAsciiN",
      (s) => toAsciiUnder(s, false),
      (r) => ({ value: r.toAsciiN, status: r.toAsciiNStatus }),
    );
    expect(failures.slice(0, 20).join("\n")).toBe("");
    expect(failures).toHaveLength(0);
  });

  it("toASCII transitional (IDNA2003 approximation): 6391/6391", () => {
    const failures = sweep(
      "toAsciiT",
      (s) => toAsciiUnder(s, true),
      (r) => ({ value: r.toAsciiT, status: r.toAsciiTStatus }),
    );
    expect(failures.slice(0, 20).join("\n")).toBe("");
    expect(failures).toHaveLength(0);
  });

  it("toUnicode: 6391/6391", () => {
    // toUnicode() is total — it falls back to the input rather than signalling.
    // On an error row either the documented fallback or the correct U-label is
    // conformant; on a clean row only the exact value is.
    const failures: string[] = [];
    for (const row of ROWS) {
      const got = toUnicode(row.source);
      if (expectsError(row.toUnicodeStatus)) {
        if (got !== row.source && !valueMatches(got, row.toUnicode)) {
          failures.push(
            `L${row.line}: ${JSON.stringify(row.source)} expected fallback or ${JSON.stringify(row.toUnicode)}, got ${JSON.stringify(got)}`,
          );
        }
      } else if (!valueMatches(got, row.toUnicode)) {
        failures.push(
          `L${row.line}: ${JSON.stringify(row.source)} expected ${JSON.stringify(row.toUnicode)}, got ${JSON.stringify(got)}`,
        );
      }
    }
    expect(failures.slice(0, 20).join("\n")).toBe("");
    expect(failures).toHaveLength(0);
  });

  it("no divergences to document under this profile (contrast: punycoder's 99.08%)", () => {
    // If a tr46 bump ever breaks this, the divergence must be triaged as a bug or
    // a documented profile difference — never silently allowlisted (per the epic).
    expect(sweep("N", (s) => toAsciiUnder(s, false), (r) => ({ value: r.toAsciiN, status: r.toAsciiNStatus }))).toEqual([]);
  });
});

describe("the flag profile is the one this suite assumes", () => {
  // Guards the premise itself: if idna.ts ever turned a check ON, the relaxation
  // above would become wrong and the sweeps would go quietly out of contract.
  it("CheckBidi is off — a B-only row is accepted", () => {
    const row = ROWS.find((r) => r.source === "\u00E0\u05D0");
    expect(row?.toAsciiNStatus).toEqual(["B5", "B6"]);
    expect(toAsciiUnder(row!.source, false)).toBe("xn--0ca24w");
    // …and the same input DOES fail once the flag is on, so the row is a real probe.
    expect(tr46.toASCII(row!.source, { transitionalProcessing: false, checkBidi: true })).toBeNull();
  });

  it("CheckJoiners is off — a ContextJ-only row is accepted", () => {
    const row = ROWS.find((r) => r.source === "\u200D");
    expect(row?.toUnicodeStatus).toEqual(["C2"]);
    expect(toAsciiUnder(row!.source, false)).toBe("xn--1ug");
    expect(
      tr46.toASCII(row!.source, { transitionalProcessing: false, checkJoiners: true }),
    ).toBeNull();
  });

  it("VerifyDnsLength is off — an over-long label is still normalized", () => {
    const long = `${"a".repeat(64)}.com`;
    expect(toAsciiUnder(long, false)).toBe(long);
  });
});

describe("normalization helpers agree with the corpus", () => {
  it("toAscii() is exactly the strict form with an input fallback (6391 rows)", () => {
    // The `never throws, always returns something` contract, exercised against
    // every hostile input in the corpus rather than a handful of fixtures.
    const failures = ROWS.filter((r) => toAscii(r.source) !== (toAsciiUnder(r.source, false) ?? r.source));
    expect(failures.map((r) => r.line)).toEqual([]);
  });

  it("hasMalformedPunycode() matches the corpus error channel on all 2384 ACE rows", () => {
    const ace = ROWS.filter((r) => /(^|\.)xn--/i.test(r.source));
    expect(ace).toHaveLength(2384);
    const failures = ace.filter(
      (r) => hasMalformedPunycode(r.source) !== expectsError(r.toUnicodeStatus),
    );
    expect(failures.map((r) => `L${r.line} ${JSON.stringify(r.source)}`)).toEqual([]);
  });
});

describe("Unicode baseline of the bundled tr46 data", () => {
  // The corpus pin and the library pin must describe the SAME Unicode version.
  // Evidence: CJK Extension J (U+323B0..U+3347B) was assigned in Unicode 17.0 and
  // is `disallowed` in 16.0. Running the 16.0 corpus against this tr46 produces
  // 13 failures at exactly these code points; the 17.0 corpus produces none.
  // These two assertions detect a tr46 pin moving to a different Unicode release
  // even before the corpus is refreshed — the U3 pin-bump signal.
  it("tr46 carries Unicode 17.0 data (CJK Extension J is assigned)", () => {
    expect(toAsciiUnder("\u{32931}.com", false)).toBe("xn--982o.com");
    expect(toAsciiUnder("\u{323B0}.com", false)).toBe("xn--031o.com");
  });

  it("code points still reserved in Unicode 17.0 remain disallowed", () => {
    expect(toAsciiUnder("\u{3FFFD}.com", false)).toBeNull();
  });

  it("is version-stamped so a pin bump is visible in every result", () => {
    expect(DATA_VERSIONS.idna).toMatch(/^tr46@\d+\.\d+\.\d+$/);
  });
});
