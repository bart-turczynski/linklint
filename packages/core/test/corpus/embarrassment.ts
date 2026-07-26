/**
 * The embarrassment corpus (LINK-rifmdydg).
 *
 * A regression net for one specific promise: *linklint should not pass an
 * obviously bad string as OK.* Every entry here is a URL that a reasonable
 * person would call plainly deceptive at a glance, and the only assertion is
 * that it does not score exactly 0.00.
 *
 * ## Why this is separate from `corpus.ts`
 *
 * The labeled corpus (`corpus.ts`) is a conformance fixture: its "deceptive"
 * rows must score AND land at or above a severity band, and every row must
 * pass today. That makes it unable to hold a string we currently miss.
 *
 * This corpus is the inverse instrument. It is allowed to contain known
 * misses, so it can record the shape of a hole *before* the fix exists.
 *
 * ## The assertion is deliberately weak
 *
 * `score > 0`. Not a band, not a reason code. That is on purpose:
 *
 *  - A band assertion freezes scoring weights, and this corpus must survive
 *    the reweighting that `LINK-cwkwbhws` is about to do.
 *  - A reason-code assertion freezes detector identity, and `LINK-cphogucn`
 *    is about to delete three detectors outright.
 *
 * The corpus constrains the *outcome* the mission cares about — "did we say
 * this was fine?" — and stays silent on how that outcome is reached.
 *
 * ## Pending entries
 *
 * An entry with `pendingIssue` set is a string we currently score 0.00 on: a
 * known, tracked miss. The test asserts such entries with `it.fails`, not
 * `it.skip`. A skipped test is silent forever; an `it.fails` test goes RED the
 * moment the entry starts scoring, which forces whoever lands the fix to
 * promote the entry to active. The corpus maintains itself.
 *
 * ## Scope: claim (a) only
 *
 * linklint defends the claim that a string is *structurally* anomalous. It
 * does not claim semantic brand knowledge. The following are therefore
 * KNOWN AND ACCEPTED zero scores, deliberately NOT in this corpus:
 *
 *     paypal-login.com       structurally clean; every label is a real word,
 *                            correctly spelled, in a normal arrangement. It
 *                            reads as suggestive only if you already know
 *                            PayPal is a brand worth impersonating.
 *     apple-id-verify.com    same. "apple", "id" and "verify" are ordinary
 *                            tokens; nothing about the string is malformed.
 *
 * Catching these requires knowing which words are brands and which brands get
 * phished — claim (b), which this project rejects. They are listed here so the
 * boundary is visible to the next reader rather than looking like an oversight.
 * If either ever scores, that is a FALSE POSITIVE to investigate, not a win.
 */

export interface EmbarrassmentEntry {
  /** The URL to inspect. */
  input: string;
  /** One line on why this is obviously bad. Required — an entry nobody can justify does not belong. */
  why: string;
  /**
   * Set when the entry currently scores 0.00, naming the issue that closes the
   * gap. Unset means the entry is an active guard and must score today.
   */
  pendingIssue?: string;
}

export const EMBARRASSMENT_CORPUS: EmbarrassmentEntry[] = [
  // ---------------------------------------------------------------------
  // Active guards — these score today. They lock in wins already paid for.
  // ---------------------------------------------------------------------
  {
    input: "https://paypa1.com",
    why: "leetspeak fold of a watchlist brand as the whole registrable domain",
  },
  {
    input: "https://g00gle.com",
    why: "double-zero fold of a watchlist brand as the whole registrable domain",
  },
  {
    input: "https://micr0soft.com",
    why: "leetspeak fold of a watchlist brand as the whole registrable domain",
  },
  {
    input: "https://paypa1.vercel.app",
    why: "brand fold hoisted onto a shared hosting suffix; since LINK-lippdgpn the label tier sees `paypa1` on its own, so this escalated from the ascii_homoglyph floor to the band paypa1.com occupies",
  },
  {
    input: "https://xn--pypal-4ve.com",
    why: "punycode-encoded non-ASCII homograph of a watchlist brand",
  },
  {
    input: "https://paypal.com.security-check.ru",
    why: "a real brand domain buried in the subdomain so the left-to-right reader stops before the true registrable domain",
  },
  {
    input: "https://login.paypal.com.evil.tk",
    why: "same embedded-domain trick, on a risky TLD",
  },
  {
    input: "https://paypa1-secure-login.com",
    why: "leetspeak fold in the first token plus a secure+login pretext; since LINK-lippdgpn the fold itself scores via brand_homoglyph rather than only incidentally via bait_tokens",
  },

  // ---------------------------------------------------------------------
  // Closed by LINK-lippdgpn — the hyphen-token tier.
  //
  // These were all 0.00. Shared root cause: `ascii_homoglyph` refuses any host
  // label containing a hyphen, and `brand_homoglyph` folded the registrable
  // domain as ONE unit, so in `paypa1-login.com` neither detector ever got to
  // look at `paypa1` on its own. `brand_homoglyph` now also tokenizes every
  // host label on `-` and joins each token against the brand LABEL set under
  // the same structural fold gate, so every one of these scores today.
  // ---------------------------------------------------------------------
  {
    input: "https://paypa1-login.com",
    why: "leetspeak fold of a watchlist brand joined to a phishing token by a hyphen",
  },
  {
    input: "https://sp0tify-app.com",
    why: "same shape against a brand that is not on the watchlist — the structural anomaly is visible without knowing the brand",
  },
  {
    input: "https://0racle-support.com",
    why: "leading-digit fold plus a support pretext; the brand tier has no leading-letter gate, so the hyphen token is enough (`ascii_homoglyph` still declines it, which is why this lands 0.50/medium not 0.60/high)",
  },
  {
    input: "https://netf1ix-billing.com",
    why: "leetspeak fold plus a payment-pretext token, hidden behind the hyphen gate",
  },
  {
    input: "https://1inkedin-verify.com",
    why: "leading-digit fold plus a verification pretext; same shape as 0racle-support.com",
  },
  {
    input: "https://amaz0n-account.com",
    why: "leetspeak fold of a watchlist brand plus an account pretext",
  },
  {
    input: "https://app1e-support.com",
    why: "leetspeak fold of a watchlist brand plus a support pretext",
  },
  {
    input: "https://goog1e-drive.com",
    why: "leetspeak fold of a watchlist brand plus a real product name",
  },
  {
    input: "https://secure-paypa1.com",
    why: "fold in the SECOND token — confirms the miss was about tokenization, not about which side of the hyphen the fold sits on",
  },
];

/** Entries that must score today. */
export const ACTIVE_ENTRIES = EMBARRASSMENT_CORPUS.filter((e) => e.pendingIssue === undefined);

/** Entries that are known misses, each pointing at the issue that fixes it. */
export const PENDING_ENTRIES = EMBARRASSMENT_CORPUS.filter((e) => e.pendingIssue !== undefined);

/**
 * Strings that score 0.00 and are ACCEPTED as out of scope under claim (a).
 * Asserted to stay at zero is NOT appropriate here — a future structural
 * signal might legitimately catch them. They are exported so the boundary is
 * documented in code rather than only in prose. See the file header.
 */
export const KNOWN_AND_ACCEPTED: readonly string[] = [
  "https://paypal-login.com",
  "https://apple-id-verify.com",
];
