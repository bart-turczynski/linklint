/**
 * Band narration coupling for the corpus registers (LINK-igpykako).
 *
 * ## Why this is not the negative-space guard
 *
 * `brand-fold-surface.test.ts` ends with a NEGATIVE-SPACE guard: no
 * `<score>/<band>` string in `brand-homoglyph.ts`, `brands.ts` or that file may
 * name a pair the pipeline produces NOWHERE. Extending that guard to `corpus/**`
 * is the obvious next move and it does not work, for two measured reasons.
 *
 *  1. It would have been GREEN ON THE ROT. The stale pair `MR !51` corrected by
 *     hand in `embarrassment.ts` was `0.50/medium` — and `0.50/medium` is a band
 *     the pipeline produces, in that very file, for `login.paypal.com.evil.tk`.
 *     A guard that only asks "does anything score this?" cannot see a pair that
 *     is live somewhere and wrong here.
 *  2. `corpus/**` narrates bands HISTORICALLY on purpose — `"was 0.75/high"`,
 *     `"0.83/critical -> 0.80/high"` — and negative space cannot tell a RECORD
 *     from a CLAIM. Those records must survive; the claims must be true.
 *
 * ## The instrument that does work: positive coupling
 *
 * Every `<score>/<band>` pair an ENTRY's prose states is either a claim about
 * that entry's own current verdict — in which case it must equal what
 * `inspect(entry.input)` returns today — or it is explicitly marked as a record
 * of something else. There is no third option, and unmarked-and-wrong is the rot
 * this file exists to catch.
 *
 * ## The exemption grammar, and why it is wider than one arrow
 *
 * The left-of-arrow shape (`0.83/critical -> 0.80/high`) is the convention an
 * earlier unit observed, and taking it on trust would have been wrong: it is the
 * OBSERVED pattern, not a rule anyone wrote down. Enumerating every band
 * narration in the registers first found 17 pairs across 12 entries, and the
 * arrow covers only 3 of them. The other historical narrations use ordinary past
 * tense — `(was 0.75/high on a legitimate host)`, `scored 0.5/medium`, `read
 * 0.30/medium under agentMode` — and two pairs are neither current nor
 * historical for their entry but CONTRASTIVE: they state a band some OTHER
 * string reaches, to say what this entry does not reach (`lands 0.80/high rather
 * than the 0.84/critical a fold that also passes ascii_homoglyph reaches`).
 *
 * So the grammar has three marked forms, each detected from the text immediately
 * around the pair rather than from tense-guessing at large:
 *
 *   SUPERSEDED  — the pair is the left half of a transition: `-> ` or `→ `
 *                 follows it. The right half stays coupled.
 *   RECORDED    — a past-tense record verb (`was`, `were`, `used to`, `scored`,
 *                 `read`, `had`) sits in the same clause immediately before it.
 *   CONTRASTED  — a comparison marker (`rather than`, `instead of`) does.
 *
 * The lookbehind window stops at `.`, `;` and `/`. Stopping at `/` is the part
 * that matters: it prevents a verb from reaching PAST an intervening band pair
 * and exempting a live claim that merely follows a record in the same sentence.
 *
 * Marked pairs are then PINNED by content below. An exemption is therefore not a
 * silent escape hatch — adding one edits a reviewed list, exactly as adding a
 * brand edits the pinned surface lists in `brand-fold-surface.test.ts`.
 *
 * ## Scope: entry prose, not file comments
 *
 * This guard reads the EXPORTED registers, so it sees `notes` / `why` /
 * `observed` and nothing else. That boundary is structural rather than chosen:
 * a band pair in a block comment above a group of rows has no single
 * `entry.input` to be coupled to, so positive coupling has nothing to say about
 * it. `corpus.ts` and `vectors.ts` carry eleven such pairs. They were checked by
 * hand when this file landed and every present-tense one was true; they remain
 * outside any automated instrument, which is a known and stated limit, not an
 * oversight.
 *
 * ## A note on `observed` in `known-false-positives.ts`
 *
 * That field has the surface grammar of a record, and its own doc comment
 * (LINK-tcrgkllv) says why it is coupled here rather than exempted: the register
 * only ever holds entries that still score — its own test tells the maintainer
 * to promote and delete an entry the moment it goes quiet — so `observed` is
 * read by every reader as a statement about what linklint says today. If it
 * drifts, it misorients.
 */
import { describe, expect, it } from "vitest";
import type { InspectOptions } from "../../src/index.js";
import { inspect } from "../../src/index.js";
import { CORPUS } from "./corpus.js";
import { EMBARRASSMENT_CORPUS } from "./embarrassment.js";
import { KNOWN_FALSE_POSITIVES } from "./known-false-positives.js";

/** One prose field belonging to one register entry. */
interface Narrated {
  readonly register: string;
  readonly input: string;
  readonly prose: string;
  readonly options?: InspectOptions | undefined;
}

const NARRATED: readonly Narrated[] = [
  ...CORPUS.flatMap((row): Narrated[] =>
    row.notes === undefined
      ? []
      : [{ register: "corpus.ts", input: row.input, prose: row.notes, options: row.options }],
  ),
  ...EMBARRASSMENT_CORPUS.map(
    (entry): Narrated => ({
      register: "embarrassment.ts",
      input: entry.input,
      prose: entry.why,
    }),
  ),
  ...KNOWN_FALSE_POSITIVES.map(
    (entry): Narrated => ({
      register: "known-false-positives.ts",
      input: entry.input,
      // Both fields are the entry's prose; `observed` is where the pair lives.
      prose: `${entry.why} ${entry.observed}`,
    }),
  ),
];

/**
 * A `<score>/<band>` pair as the registers write it: one leading digit, an
 * optional fractional part of any length (`0.5`, `0.50` and `0.575` all occur),
 * a slash, and a `Severity` member.
 */
const BAND_PAIR = /\b(\d(?:\.\d+)?)\s*\/\s*(info|low|medium|high|critical)\b/g;

/** Marked-historical forms. See the exemption grammar in the header. */
const SUPERSEDED = /^\s*(?:->|→)/;
const RECORDED = /\b(?:was|were|used to|scored|read|had)\b[^.;/]{0,48}$/i;
const CONTRASTED = /\b(?:rather than|instead of)\b[^.;/]{0,48}$/i;

type Marker = "superseded" | "recorded" | "contrasted" | null;

function markerFor(prose: string, at: number, pair: string): Marker {
  if (SUPERSEDED.test(prose.slice(at + pair.length))) return "superseded";
  const before = prose.slice(0, at);
  if (RECORDED.test(before)) return "recorded";
  if (CONTRASTED.test(before)) return "contrasted";
  return null;
}

interface Occurrence {
  readonly register: string;
  readonly input: string;
  readonly pair: string;
  readonly score: number;
  /** Digits after the decimal point, so `0.84` is compared at its own precision. */
  readonly precision: number;
  readonly severity: string;
  readonly marker: Marker;
  readonly options?: InspectOptions | undefined;
}

const OCCURRENCES: readonly Occurrence[] = NARRATED.flatMap((entry) =>
  [...entry.prose.matchAll(BAND_PAIR)].map((match): Occurrence => {
    const [pair, scoreText = "", severity = ""] = match;
    const dot = scoreText.indexOf(".");
    return {
      register: entry.register,
      input: entry.input,
      pair,
      score: Number(scoreText),
      precision: dot === -1 ? 0 : scoreText.length - dot - 1,
      severity,
      marker: markerFor(entry.prose, match.index, pair),
      options: entry.options,
    };
  }),
);

const COUPLED = OCCURRENCES.filter((o) => o.marker === null);
const MARKED = OCCURRENCES.filter((o) => o.marker !== null);

const describeOccurrence = (o: Occurrence): string =>
  `${o.register} ${o.input} — ${o.pair} (${o.marker})`;

/**
 * Every band narration the grammar reads as a record rather than a claim.
 * Pinned so an exemption cannot be added without review: a new line here is a
 * new piece of prose asserting the pipeline USED to do something, and that is
 * exactly the kind of sentence that should be read before it lands.
 */
const PINNED_MARKED_NARRATIONS: readonly string[] = [
  "corpus.ts https://api.openai-com.io/ — 0.50/medium (recorded)",
  "corpus.ts https://api.openai-login.com — 0.50/medium (recorded)",
  "corpus.ts https://blog.example.com/download?data=report2024 — 0.30/medium (recorded)",
  "corpus.ts https://login.paypal.com.account.evil.com/ — 0.575/high (superseded)",
  "corpus.ts https://www.eu.playstation.com/update.exe — 0.75/high (recorded)",
  "corpus.ts intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end — 0.00/info (recorded)",
  "corpus.ts intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end — 0.90/critical (recorded)",
  "corpus.ts mailto:someone@example.com — 0.5/medium (recorded)",
  "embarrassment.ts https://0racle-support.com — 0.84/critical (contrasted)",
  "embarrassment.ts https://login.paypal.com.evil.tk — 0.575/high (superseded)",
  "embarrassment.ts https://paypa1-secure-login.com — 0.83/critical (superseded)",
];

describe("corpus band narrations are coupled to the live verdict (LINK-igpykako)", () => {
  it("states a true band for every unmarked pair in an entry's prose", () => {
    const stale = COUPLED.flatMap((o) => {
      const result = inspect(o.input, o.options);
      if (result.status !== "ok" || result.score === null || result.severity === null) {
        return [`${o.register} ${o.input}: states ${o.pair} but does not inspect to a verdict`];
      }
      // Compare at the precision the prose chose, so `0.84` matches a live
      // 0.8400000000000001 and `0.575` still has to be right to three places.
      const tolerance = 0.5 * 10 ** -o.precision;
      const scoreOk = Math.abs(result.score - o.score) < tolerance;
      const bandOk = result.severity === o.severity;
      return scoreOk && bandOk
        ? []
        : [
            `${o.register} ${o.input}: prose says ${o.pair}, ` +
              `pipeline says ${result.score.toFixed(Math.max(2, o.precision))}/${result.severity}`,
          ];
    });
    expect(
      stale,
      "An unmarked <score>/<band> pair reads as a claim about this entry's CURRENT verdict. " +
        "Either correct the pair, or mark it as a record (`was …`, `scored …`, `X -> Y`, " +
        "`… rather than X`) and add it to PINNED_MARKED_NARRATIONS.",
    ).toEqual([]);
  });

  it("pins every pair the grammar exempts as a record", () => {
    expect(MARKED.map(describeOccurrence).sort()).toEqual([...PINNED_MARKED_NARRATIONS].sort());
  });

  it("keeps coupled pairs in the registers, so the guard cannot pass vacuously", () => {
    // If a refactor ever stops the registers from narrating bands at all, the
    // first assertion above passes over an empty list and proves nothing.
    expect(COUPLED.length).toBeGreaterThan(0);
    expect(OCCURRENCES.length).toBe(COUPLED.length + MARKED.length);
  });

  it("reads the arrow's right half as a claim, not part of the record", () => {
    // The convention this guard was almost built on would have exempted the
    // whole transition. Only the left half is superseded; the right half is the
    // live verdict and is the half most likely to rot.
    const rightHalves = COUPLED.filter((o) => o.register === "embarrassment.ts").map((o) => o.pair);
    expect(rightHalves).toContain("0.500/medium");
    expect(rightHalves).toContain("0.80/high");
  });
});
