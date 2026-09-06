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
 * An entry is not a measurement. `LINK-wtdpntox` filed the hash-router class as a
 * KNOWN UNQUANTIFIED EXPOSURE, not a sized cost, on the premise that nobody has a
 * benign corpus with fragments to put a number on it. One pinned string makes the
 * shape visible and reviewable; on its own it says nothing about how much of the
 * real web has this shape. Do not read a short list as a small class.
 *
 * That premise has since been tested and is FALSE — the corpus is obtainable, and
 * the class is now sized. See "The sourcing, and the number" below. The rule the
 * paragraph states still holds for every OTHER entry: an entry is a pin, and a pin
 * is not a rate until someone goes and measures the population.
 *
 * And an entry is not a licence to tune. Suppressing an unmeasured class to make
 * an unmeasured class disappear is the self-confirming move `docs/architecture.md`
 * §6 warns about. The register exists so the exposure stays visible until someone
 * measures it, not so it can be quietly fitted away. Note what the measurement
 * below did NOT do: it did not move a weight, add an exemption, or touch a
 * detector. Sizing a class and suppressing it are different acts, and only the
 * first one is licensed here.
 *
 * ## The sourcing, and the number (LINK-wtdpntox)
 *
 * The question was whether a benign corpus of URLs WITH FRAGMENTS is obtainable at
 * all. It is. The route is Common Crawl, but not the obvious part of it.
 *
 * ### Why the standing objection does not apply
 *
 * The reason everyone gives for why Common Crawl cannot answer this is that a
 * crawler strips the fragment before fetching, so no WARC request URL ever carries
 * one. That is true, and it was re-checked rather than recalled: 300 CDX index
 * records for `developer.mozilla.org/*` in `CC-MAIN-2026-34` contain ZERO `#`.
 *
 * But it is an argument about FETCHED URLs, and it does not reach the WAT records.
 * WAT holds extracted page metadata, including a `Links` array of the page's
 * anchor `href` values AS WRITTEN IN THE MARKUP — raw and unresolved, relative
 * forms and all. Nothing fetches those, so nothing strips them. Fragments survive
 * intact. The stripping argument and the outlink records are about two different
 * URL populations, and conflating them is what made this look unobtainable.
 *
 * ### Method
 *
 * The head (~26 MB compressed) of one WAT file from each of nine segments of
 * `CC-MAIN-2026-34`, decompressed, every `A@/href` extracted, resolved against its
 * own page URL, filtered to http(s) with a non-empty fragment, then deduplicated
 * by exact URL and run through the BUILT `inspect()` — the shipping detector, not
 * a reimplementation of it.
 *
 *   34,420 pages -> 4,508,773 anchor hrefs -> 233,209 carrying `#`
 *   -> 101,787 unique absolute http(s) URLs with a non-empty fragment
 *
 * Of those 101,787: 1,233 have a fragment containing `=` (parseable as pairs at
 * all), 1,035 are SPA hash routes (fragment begins `/`), and 166 are the pinned
 * entry's exact shape — a hash route with its own query, `#/path?a=b`.
 *
 * ### The number
 *
 *   26 of 101,787 fire `open_redirect_param` on the fragment surface.
 *
 *     0.0255%  of all unique URLs with a fragment
 *     2.1087%  of fragments parseable as pairs
 *     0.6024%  of the pinned entry's exact shape (1 of 166)
 *
 * All 26 were read by hand and all 26 are benign. Not one is an open redirect.
 *
 * ### What the adjudication changed about the shape of the class
 *
 * This is the part worth more than the rate. The pinned entry is an SPA hash
 * router, and the ticket frames the whole class that way. The real population is
 * not shaped like that at all:
 *
 *   17  `addtoany.com/share#url=...`     share widget
 *    3  `twitter.com/share?...#...url=`  share intent
 *    2  `reader.yodao.com/#url=...`      feed reader
 *    2  `blog.photo.sina.com.cn/showpic.html#url=...`  photo viewer
 *    1  `linkedin.com/shareArticle?...#...url=`        share intent
 *    1  `trust.wjdhcms.com/#/pc?url=...`               an actual hash router
 *
 * Twenty-one of twenty-six are share widgets and readers. EXACTLY ONE is the hash
 * router the entry pins. AddToAny puts the shared URL in the fragment BY DESIGN,
 * precisely so the URL being shared is never sent to AddToAny's server — the
 * fragment is doing privacy work, and a cross-authority absolute URL in it is the
 * feature rather than a smell. The four share-intent hits are a different accident
 * again: a literal HASHTAG inside the share `text=` opens a fragment mid-query, and
 * the `url=` parameter that follows lands on the fragment surface by pure lexical
 * position. So the entry pins a real class under a misleading name. Anyone sizing
 * remediation should price the share-widget convention first; the SPA hash router
 * is the rare member, not the representative one.
 *
 * ### The second band, and why it is a second entry (LINK-gdarhprp)
 *
 * The adjudication above sizes the class. It does not report its worst verdict,
 * because the sample dump it was read from listed only the fragment-attributed
 * reason code, which hid a co-firing detector. Re-run against the built
 * `inspect()`, 4 of the same 26 hits score 0.61/high rather than 0.40/medium, and
 * all four are AddToAny share links that were hand-adjudicated benign.
 *
 * The mechanism generalises, which is why it is pinned rather than noted. A share
 * widget percent-encodes the URL being shared. When that URL ALREADY contains
 * percent-encoded non-ASCII - Devanagari `%E0%A4%85` in the entry below - encoding
 * it a second time yields `%25E0%25A4%2585`, and double-encoding is exactly what
 * `encoding_obfuscation` is built to notice. So it co-fires with
 * `open_redirect_param` and the pair clears the high band. This is not a rare
 * accident: it is the deterministic output of the share-widget convention applied
 * to any non-ASCII URL, which is to say to most of the non-English web. The
 * 4-of-26 rate inherits the served-markup floor caveat above.
 *
 * Severity is the part that costs something, because severity is what the
 * enforcement guard acts on. `docs/enforcement.md` documents `LINKLINT_FAIL_ON` as
 * defaulting to `high`, so this is not a threshold a user opts into by taking our
 * advice - at the shipped default these benign share links are BLOCKED rather than
 * merely scored, out of the box, on the non-English web.
 *
 * Why a SECOND ENTRY and not a range on the existing one. `observed` is coupled to
 * live behaviour through `band-narration.test.ts`, and that coupling is the whole
 * value of the field. One assertion cannot pin "somewhere between 0.40/medium and
 * 0.61/high", so a range would convert a mechanically-checked field into prose
 * that drifts silently - the precise failure this register exists to prevent. Two
 * rows keep one pin per observable verdict. They also repair the naming problem
 * the section above records: the first row is named for an SPA hash router that is
 * 1 of 26 real hits, while the share widgets it stands next to are 21 of 26.
 *
 * Read the two rows as ONE class with two bands, not as two classes. Same detector
 * on the same fragment surface; the second simply carries a second detector
 * because the shared URL was non-ASCII. And nothing here licenses tuning either
 * band away: `encoding_obfuscation` is doing its stated job on a genuinely
 * double-encoded string. Recording the high band is the deliverable; making it
 * disappear is a separate decision nobody has taken.
 *
 * ### Representativeness, stated against our own interest
 *
 * The honest caveats, including the one that cuts the wrong way:
 *
 *  - The denominator is "the web as crawled", NOT "verified benign URLs". The
 *    26-URL numerator was adjudicated by hand; the 101,787 denominator was not.
 *  - One crawl, nine segments, head-of-file. Head-of-file is not a uniform random
 *    sample within a segment.
 *  - MOST IMPORTANT, AND IT CUTS AGAINST THE LOW NUMBER ABOVE: WAT captures anchor
 *    hrefs present in SERVED HTML. A hash route a client-side router generates
 *    after hydration is never an `href` in the markup and cannot appear here at
 *    all. SPA routes are therefore plausibly UNDER-counted, and 0.60% of the
 *    pinned shape is a floor rather than an estimate. Do not quote the rate as if
 *    it settled the SPA case; it settles the served-markup case.
 *  - Dedup is by exact URL, so one template repeated across a site counts once.
 *    That shrinks AddToAny's share relative to raw link volume.
 *
 * ### The routes that did NOT work, so nobody re-derives them
 *
 *  - Common Crawl CDX / WARC request URLs — fragments stripped before fetch.
 *    Measured, not assumed: 300 records, 0 with `#`.
 *  - HTTP Archive via BigQuery — `bq` and `gcloud` are installed here but the
 *    tokens are expired, re-auth needs an interactive browser, and no billing
 *    project is set. Even authenticated it would bill a third party's project for
 *    the scan. Unreachable non-interactively; not attempted further.
 *  - Cisco Umbrella top-1M — 1,000,000 rows, 10 carry a scheme, ZERO carry a
 *    fragment. Origin and domain lists cannot answer a fragment question, as
 *    expected. CrUX has the same shape and the same answer.
 *  - Client-side sources (browser history, bookmarks, live scraping) were NOT
 *    needed once the public route worked, and are worse on the merits: one
 *    person's browsing is not the web, and a reviewer cannot reproduce it.
 *
 * The measurement is reproducible from public data with curl and node, no
 * credentials and no paid service. Re-run it against a newer crawl before trusting
 * the rate; nothing here is pinned by a test, and these numbers are a snapshot.
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
  // SIZED — see "The sourcing, and the number" in the header. 26 of 101,787 real
  // fragment-bearing anchor hrefs from Common Crawl fire this, all 26 benign; the
  // shape below is 1 of those 26. Read the header before citing the entry as
  // typical: the class is dominated by share widgets, not by hash routers, and
  // WAT cannot see routes a client-side router builds after hydration.
  {
    input: "https://example.com/#/route?url=https://cdn.example.org/x",
    why: "an ordinary single-page-app hash route whose own query happens to carry a CDN URL under a parameter named `url`; by the detector's stated premise it is a true positive, by ordinary web practice it is a normal SPA link",
    issue: "LINK-wtdpntox",
    observed: "0.40/medium [open_redirect_param] — fragment redirect parameter 'url' points off-site to 'example.org'",
  },
  // The same class at its high band — see "The second band" in the header. 4 of
  // those same 26 hits score here rather than at 0.40/medium, all four AddToAny
  // share links, all four benign. Kept as its own row because `observed` is pinned
  // per verdict and cannot express a range. Do NOT tune `encoding_obfuscation` so
  // it stops co-firing: it is correctly reporting a genuinely double-encoded
  // string, and the entry exists to keep that cost visible, not to license its
  // removal.
  {
    input:
      "https://www.addtoany.com/share#url=https%3A%2F%2Fbishnumun.gov.np%2Fcontent%2F%25E0%25A4%2585%25E0%25A4%25A8&title=x",
    why: "an ordinary AddToAny share link, which puts the shared URL in the fragment by design so that the URL being shared is never sent to AddToAny's server; the shared URL is a Nepali government page whose path is already percent-encoded Devanagari, so the widget's own encoding of it comes out double-encoded by arithmetic, with nothing concealed and nothing to conceal.",
    issue: "LINK-gdarhprp",
    observed:
      "0.61/high [open_redirect_param, encoding_obfuscation] — fragment redirect parameter 'url' points off-site to 'bishnumun.gov.np', and the doubly percent-encoded Devanagari path reads as '%25' double-encoding",
  },
];
