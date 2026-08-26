import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { WEIGHTS, inspect } from "../src/index.js";
import { CORPUS, type CorpusRow } from "./corpus/corpus.js";
import { REALISTIC_MULTILINGUAL_URLS } from "./corpus/vectors.js";
import { REPO_ROOT } from "./doc-sweep.js";

/**
 * T2.3 (LINK-ibwuayzo) — low-byte-truncation code points.
 *
 * A code point above U+007F whose low byte is a dangerous ASCII byte, isolated
 * between two ASCII alphanumerics. A lossy UTF-16-to-byte narrowing materializes
 * the byte, so no byte-scan of the input can see it — this is the class
 * `control_char` cannot reach even though it handles every direct form.
 *
 * The ASCII-sandwich guard is the load-bearing part of the design and is
 * asserted in both directions below. Without it, the firing condition would be
 * "truncation-reachable", which covers 492 everyday CJK characters and would
 * flag a large share of real Chinese and Japanese URLs.
 *
 * ## Why the counts are derived here rather than written down (LINK-dhtmcqva)
 *
 * The slice that shipped this detector measured two things and then wrote both
 * numbers into prose in three places: a docstring, a comment in this file, and
 * `docs/reason-codes.md`. All three rotted, because a corpus grows and prose
 * does not, and nothing executed any of them. The last block in this file
 * derives both figures from `CORPUS` and `REALISTIC_MULTILINGUAL_URLS` and
 * prints them, and it also asserts that neither prose site has gone back to
 * quoting a count. The measurement is a test run, not a sentence.
 */

const reasons = (url: string) => inspect(url, { agentMode: true }).reasons.map((r) => r.code);

describe("low_byte_truncation — fires on a dangerous low byte inside an ASCII sandwich", () => {
  it.each([
    ["https://example.com/a嘊b", "U+560A narrows to LF"],
    ["https://example.com/a嘍b", "U+560D narrows to CR"],
    ["https://example.com/aĊb", "U+010A narrows to LF — the family is unbounded"],
    ["https://example.com/x有y", "U+6709 (有) narrows to TAB"],
    ["https://example.com/1下2", "U+4E0B (下) narrows to VT, digits count as alphanumeric"],
    ["https://example.com/a一b", "U+4E00 (一) narrows to NUL"],
    ["https://example.com/a圯b", "U+572F narrows to '/' — re-parses the authority"],
    ["https://example.com/?q=a局b", "query component is scanned"],
    ["https://example.com/#a局b", "fragment component is scanned"],
  ])("%s (%s)", (url) => {
    expect(reasons(url)).toContain("low_byte_truncation");
  });

  it("scores 0.6 — parity with control_char, which catches the direct form", () => {
    // The truncation variant is strictly harder to see than a raw or
    // percent-encoded newline, so parity is the defensible floor: pricing it
    // higher would assert it is worse than an actual embedded newline.
    // Revisit is tracked at LINK-tyjxigyc.
    expect(WEIGHTS.low_byte_truncation).toBe(0.6);
    expect(WEIGHTS.low_byte_truncation).toBe(WEIGHTS.control_char);
  });

  it("catches the zero-width joiner in g<U+200D>oogle.com, whose low byte is 0x0D", () => {
    // Found independently by this check on a corpus row that was already a known
    // attack for a different reason. How much of the corpus it reaches is
    // derived at the bottom of this file rather than asserted here.
    expect(reasons("https://g‍oogle.com/")).toContain("low_byte_truncation");
  });
});

describe("low_byte_truncation — the ASCII sandwich is required, not incidental", () => {
  /**
   * The realistic-multilingual set, read from the SAME array the corpus rows in
   * `vectors.ts` are generated from. Before LINK-dhtmcqva the two pins were
   * hand-written and covered different subsets — 5 rows in `vectors.ts`, 6 here,
   * 7 distinct between them — while the prose claimed a measured 17. There is
   * now one array and both pins widen with it.
   */
  it.each(REALISTIC_MULTILINGUAL_URLS.map((entry) => [entry.input, entry.notes] as const))(
    "%s (%s)",
    (url) => {
      expect(reasons(url)).not.toContain("low_byte_truncation");
    },
  );

  it("covers every script the detector's prose names — JP, CN, KR, RU, GR", () => {
    // Each script is present by construction rather than by a count: a set that
    // silently lost its Greek or Hangul rows would still satisfy a size check.
    const inputs = REALISTIC_MULTILINGUAL_URLS.map((entry) => entry.input).join("\n");
    for (const [script, probe] of [
      ["Hiragana/Katakana", /[぀-ヿ]/u],
      ["Han", /\p{Script=Han}/u],
      ["Hangul", /\p{Script=Hangul}/u],
      ["Cyrillic", /\p{Script=Cyrillic}/u],
      ["Greek", /\p{Script=Greek}/u],
    ] as const) {
      expect(probe.test(inputs), `no ${script} URL in the realistic-multilingual set`).toBe(true);
    }
  });

  it("stays quiet on non-ASCII whose low byte is harmless", () => {
    // U+4E2D (中) low byte 0x2D is '-', U+6587 (文) low byte 0x87 is not ASCII.
    expect(reasons("https://example.com/a中b")).not.toContain("low_byte_truncation");
    expect(reasons("https://example.com/a文b")).not.toContain("low_byte_truncation");
  });

  it("does not fire on a plain ASCII URL or on a real embedded control character", () => {
    expect(reasons("https://example.com/a/b")).not.toContain("low_byte_truncation");
    // A raw LF is control_char / invisible_char territory: the byte is really
    // there, so this check has nothing to add.
    expect(reasons("https://example.com/a\nb")).not.toContain("low_byte_truncation");
    expect(reasons("https://example.com/a%0Ab")).not.toContain("low_byte_truncation");
  });
});

/**
 * Flatten prose to one line before matching it (LINK-dhtmcqva).
 *
 * Both prose sites hard-wrap, and both carry a per-line marker: ` * ` in the
 * docstring, `> ` in a blockquote, plus the two-space continuation indent of a
 * markdown bullet. A raw `includes()` against a sentence that spans a wrap
 * matches NOTHING and the assertion passes vacuously — the failure mode this
 * ticket recorded four times in four forms. Swapping this function for the
 * identity turns the pointer assertions below RED, which is how it was checked.
 */
const flatten = (text: string): string =>
  text
    .replace(/^[ \t]*(?:\*|>)+[ \t]?/gm, " ")
    .replace(/\s+/g, " ")
    .trim();

const DETECTOR_SRC = join(
  REPO_ROOT,
  "packages",
  "core",
  "src",
  "detectors",
  "low-byte-truncation.ts",
);
const REASON_CODES_DOC = join(REPO_ROOT, "docs", "reason-codes.md");

/** The one sentence both prose sites must carry instead of a measurement. */
const POINTER =
  "the realistic-multilingual set is `REALISTIC_MULTILINGUAL_URLS` in " +
  "`packages/core/test/corpus/vectors.ts`, and " +
  "`packages/core/test/low-byte-truncation.test.ts` pins every member quiet and " +
  "reports the derived counts";

/** A ratio of the `17/17 realistic` or `1/220 corpus` shape. */
const RESTATED_RATIO = /\b\d[\d,]*\s*\/\s*\d[\d,]*\s+(?:realistic|corpus)\b/i;
/** A bare count of the `17 realistic multilingual URLs` shape. */
const RESTATED_COUNT = /\b\d[\d,]*\s+(?:realistic multilingual|corpus)\s+URLs?\b/i;

/** The `low_byte_truncation` section of `docs/reason-codes.md`, and only it. */
function reasonCodesSection(): string {
  const doc = readFileSync(REASON_CODES_DOC, "utf8");
  const start = doc.search(/^### `low_byte_truncation`/m);
  expect(start, "docs/reason-codes.md has no low_byte_truncation section").toBeGreaterThan(-1);
  const rest = doc.slice(start + 1);
  const end = rest.search(/^### /m);
  return end === -1 ? rest : rest.slice(0, end);
}

describe("low_byte_truncation — the measurement is derived, not quoted (LINK-dhtmcqva)", () => {
  const fires = (row: CorpusRow): boolean =>
    inspect(row.input, { ...(row.options ?? {}), agentMode: true }).reasons.some(
      (r) => r.code === "low_byte_truncation",
    );
  const firing = CORPUS.filter(fires);

  it("reports the derived counts", () => {
    // Visible in test output. This is where a reader gets the numbers that used
    // to sit in three prose sites and rot there.
    console.log(
      `[low_byte_truncation] corpus rows=${CORPUS.length} firing=${firing.length} ` +
        `realistic-multilingual set=${REALISTIC_MULTILINGUAL_URLS.length} ` +
        `(all quiet: ${String(REALISTIC_MULTILINGUAL_URLS.every((e) => !reasons(e.input).includes("low_byte_truncation")))})`,
    );
    expect(CORPUS.length).toBeGreaterThan(REALISTIC_MULTILINGUAL_URLS.length);
    expect(REALISTIC_MULTILINGUAL_URLS.length).toBeGreaterThan(0);
  });

  it("fires on no benign or info corpus row — the CJK false-positive class is empty", () => {
    // This is the property the stale "1/220" was really asserting. It is stated
    // as a set so it cannot go stale: a new false positive names itself.
    expect(firing.filter((row) => row.label !== "deceptive").map((row) => row.input)).toEqual([]);
  });

  it("is the sole scoring reason on exactly the two fixtures its own slice authored", () => {
    const scoringCodes = (row: CorpusRow): string[] =>
      inspect(row.input, { ...(row.options ?? {}), agentMode: true })
        .reasons.filter((r) => (r.weight ?? 0) > 0)
        .map((r) => r.code);
    const alone = firing.filter((row) => scoringCodes(row).length === 1).map((row) => row.input);
    expect(alone).toEqual(["https://example.com/a嘊b", "https://example.com/x有y"]);

    // Every other firing row was already saturated at 1.0 by invisible_char
    // before this detector existed, so the code adds evidence there rather than
    // a verdict. LINK-tyjxigyc's weight decision rested on this; it is checked
    // here instead of being taken from that issue's closing note.
    for (const row of firing) {
      if (alone.includes(row.input)) continue;
      const result = inspect(row.input, { ...(row.options ?? {}), agentMode: true });
      expect(result.reasons.map((r) => r.code)).toContain("invisible_char");
      expect(result.score).toBe(1);
    }
  });

  it("the detector docstring points at this file instead of quoting a count", () => {
    const src = flatten(readFileSync(DETECTOR_SRC, "utf8"));
    expect(src).toContain(POINTER);
    expect(RESTATED_RATIO.test(src), `docstring restates a ratio: ${src.match(RESTATED_RATIO)?.[0] ?? ""}`).toBe(false);
    expect(RESTATED_COUNT.test(src), `docstring restates a count: ${src.match(RESTATED_COUNT)?.[0] ?? ""}`).toBe(false);
  });

  it("the docs/reason-codes.md section points here instead of quoting a count", () => {
    const section = flatten(reasonCodesSection());
    expect(section).toContain(POINTER);
    expect(RESTATED_RATIO.test(section), `doc restates a ratio: ${section.match(RESTATED_RATIO)?.[0] ?? ""}`).toBe(false);
    expect(RESTATED_COUNT.test(section), `doc restates a count: ${section.match(RESTATED_COUNT)?.[0] ?? ""}`).toBe(false);
  });
});
