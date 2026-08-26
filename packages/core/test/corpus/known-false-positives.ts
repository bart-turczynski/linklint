/**
 * The known-false-positive register (LINK-tsvngawn).
 *
 * The mirror image of `embarrassment.ts`. That corpus holds strings a reasonable
 * person calls plainly deceptive which linklint currently passes as OK — misses.
 * This one holds strings a reasonable person calls plainly ORDINARY which
 * linklint currently SCORES — overreach.
 *
 * ## Why neither existing register could hold these
 *
 * `corpus.ts` has four labels and none of them fits. A `benign` row asserts
 * `score === 0`, so a string that scores today cannot be added as one without
 * turning the gate red; and `precision-recall.test.ts` asserts the benign set has
 * ZERO false positives, which is exactly the assertion such a row would break.
 * The corpus is a conformance fixture: it can only hold what already passes.
 *
 * `KNOWN_AND_ACCEPTED` in `embarrassment.ts` is not it either, and the mistake is
 * worth naming because it is easy to make. That list is the accepted
 * FALSE-NEGATIVE register — `docs/architecture.md` describes its two entries as
 * scoring `0.00`, out of scope under claim (a), and says outright that "if either
 * string ever starts scoring, that is a false positive to investigate rather than
 * a win". Filing a string that scores `0.40` under a heading whose documented
 * meaning is "scores 0.00 and should" is a category error, and it would assert
 * nothing: the only test that reads the list checks that its entries are NOT
 * embarrassment-corpus entries.
 *
 * ## The assertion, and why it is inverted
 *
 * Each entry states the verdict we WANT — `score === 0` — and the test declares
 * it with `it.fails`, borrowing the idiom `embarrassment.ts` uses for its pending
 * misses. So the code says what it means (this string should be quiet), records
 * honestly that it is not quiet today, and goes RED the moment the exposure is
 * closed, which forces whoever closes it to promote the entry to a plain `benign`
 * corpus row. The register maintains itself and nothing here endorses the current
 * verdict.
 *
 * ## What an entry is NOT
 *
 * An entry is not a measurement. `LINK-wtdpntox` is explicit that the hash-router
 * class is a KNOWN UNQUANTIFIED EXPOSURE, not a sized cost: nobody has a benign
 * SPA corpus with fragments to put a number on it. One pinned string makes the
 * shape visible and reviewable; it says nothing about how much of the real web
 * has this shape. Do not read a short list as a small class.
 *
 * And an entry is not a licence to tune. Suppressing an unmeasured class to make
 * an unmeasured class disappear is the self-confirming move `docs/architecture.md`
 * §6 warns about. The register exists so the exposure stays visible until someone
 * measures it, not so it can be quietly fitted away.
 */

export interface KnownFalsePositive {
  /** The URL to inspect. */
  input: string;
  /** One line on why a reasonable person reads this as ordinary. Required. */
  why: string;
  /** The issue tracking the exposure. Required — an untracked FP is just a bug. */
  issue: string;
  /**
   * The verdict as it stands TODAY, kept current — not a filing-time snapshot.
   *
   * `band-narration.test.ts` reads the `<score>/<band>` pair out of this text and
   * compares it against a fresh `inspect(input)`, so the field turns red as soon as
   * the number moves. That coupling is the point rather than an accident of the
   * guard's reach. This register's own `it.fails` assertion flips only when an entry
   * reaches score 0, so a PARTIAL fix — 0.40 dropping to 0.20 — leaves it silent: the
   * score is still non-zero, the inner assertion still throws, which is what `it.fails`
   * expects, and the test stays green while the exposure has visibly shrunk.
   * A coupled `observed` reports that movement, and the movement is what a reader of
   * a register of unfixed defects came here to learn: is this getting better?
   *
   * Why the record-vs-claim doctrine does NOT exempt this field. It has the surface
   * grammar of a record, and `band-narration.test.ts` could mark it historical to
   * quiet the guard — resist that. The register holds entries that STILL score; the
   * moment one goes quiet the maintainer promotes it to a benign corpus row and
   * deletes it from here. So a reader takes this line as a statement about what
   * linklint says now, and a snapshot left to drift in that position misorients
   * instead of orienting. It is also precisely the sort of figure nobody re-derives:
   * `LINK-fodmjqdp` closed on one stale total that had rotted in four places at once.
   * A register of unfixed defects wants its numbers live. Leave it coupled.
   */
  observed: string;
}

export const KNOWN_FALSE_POSITIVES: readonly KnownFalsePositive[] = [
  {
    input: "https://example.com/#/route?url=https://cdn.example.org/x",
    why: "an ordinary single-page-app hash route whose own query happens to carry a CDN URL under a parameter named `url`; by the detector's stated premise it is a true positive, by ordinary web practice it is a normal SPA link",
    issue: "LINK-wtdpntox",
    observed: "0.40/medium [open_redirect_param] — fragment redirect parameter 'url' points off-site to 'example.org'",
  },
];
