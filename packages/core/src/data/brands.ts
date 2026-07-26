/**
 * Curated brand watchlist. The shared, authoritative data source the brand
 * detectors consume: the **registrable brand domain** (`paypal.com`) feeds the
 * domain-based brand family — `brand_lookalike` (Damerau-Levenshtein distance),
 * `brand_homoglyph` (ASCII digit fold), `brand_soundsquat`, `brand_bitsquat`,
 * and `homograph_skeleton_collision` — against an input's registrable domain.
 *
 * High-abuse impersonation targets only — banks, big tech, payment processors,
 * major commerce/logistics, and a few perennial phishing favourites. Kept
 * deliberately conservative (~50–200 entries): precision comes first (SC-2).
 *
 * Entries are normalized: lowercase domain (registrable, no scheme/path/www).
 *
 * Version-pinned via dataVersions.brands. Plain module exports under src/data/,
 * consumed via static import — same tree-shakeable pattern as risky-tlds.ts /
 * confusables.ts.
 *
 * ── Inclusion charter (LINK-stnruoge) ──────────────────────────────────────
 * Two tests, both required. Brand fame is not one of them.
 *
 * 1. HARM IN ONE STEP. If a user is deceived about this domain, do they lose
 *    money, credentials, or an API key in a single step? If the worst case is
 *    embarrassment or a wasted click, it does not belong here.
 *
 * 2. FOLD-REACHABILITY, measured. A brand earns structural coverage only through
 *    pre-images under the ASCII digit fold (`0`->o, `1`->l, `5`->s). A label with
 *    no `o`, `l`, or `s` has NO pre-images and buys nothing in the structural
 *    tier: `huggingface` is the clearest case, and `openai` reaches only the
 *    laxer 0.50/medium band via `0penai.com`. Such an addition needs a stated
 *    non-fold justification — edit-distance or soundsquat coverage, say — or it
 *    should be declined. Do not assume a famous name is carrying weight.
 *
 * Hard cap: ~150 entries. Past that, precision (SC-2) and the review cost of the
 * firing surface both degrade faster than coverage improves.
 *
 * Every addition or removal changes the pinned surface in
 * `test/brand-fold-surface.test.ts`, which fails with the exact added and
 * removed strings. That diff IS the review — never regenerate it to make the
 * test pass without reading what moved.
 */

/** A single brand on the watchlist. */
export interface BrandEntry {
  /** Registrable brand domain, lowercase (e.g. `paypal.com`). */
  readonly domain: string;
}

/**
 * The watchlist. Order is not significant. Keep entries lowercase.
 */
export const BRAND_WATCHLIST: readonly BrandEntry[] = [
  // ── payments / finance ────────────────────────────────────────────────
  { domain: "paypal.com" },
  { domain: "stripe.com" },
  { domain: "venmo.com" },
  { domain: "wise.com" },
  { domain: "squareup.com" },
  { domain: "cash.app" },
  { domain: "coinbase.com" },
  { domain: "binance.com" },
  { domain: "kraken.com" },
  { domain: "blockchain.com" },
  { domain: "metamask.io" },
  { domain: "ledger.com" },
  { domain: "trezor.io" },
  { domain: "chase.com" },
  { domain: "wellsfargo.com" },
  { domain: "bankofamerica.com" },
  { domain: "citibank.com" },
  { domain: "capitalone.com" },
  { domain: "usbank.com" },
  { domain: "barclays.co.uk" },
  { domain: "hsbc.com" },
  { domain: "lloydsbank.com" },
  { domain: "natwest.com" },
  { domain: "santander.com" },
  { domain: "revolut.com" },
  { domain: "monzo.com" },
  { domain: "n26.com" },
  { domain: "americanexpress.com" },
  { domain: "mastercard.com" },
  { domain: "visa.com" },
  { domain: "westernunion.com" },
  { domain: "fidelity.com" },
  { domain: "schwab.com" },
  { domain: "vanguard.com" },
  { domain: "robinhood.com" },
  { domain: "intuit.com" },
  { domain: "turbotax.intuit.com" },
  { domain: "klarna.com" },
  { domain: "zellepay.com" },

  // ── big tech / platforms / identity ───────────────────────────────────
  { domain: "google.com" },
  { domain: "youtube.com" },
  { domain: "apple.com" },
  { domain: "microsoft.com" },
  { domain: "live.com" },
  { domain: "amazon.com" },
  { domain: "meta.com" },
  { domain: "facebook.com" },
  { domain: "instagram.com" },
  { domain: "whatsapp.com" },
  { domain: "messenger.com" },
  { domain: "x.com" },
  { domain: "linkedin.com" },
  { domain: "tiktok.com" },
  { domain: "snapchat.com" },
  { domain: "pinterest.com" },
  { domain: "reddit.com" },
  { domain: "discord.com" },
  { domain: "telegram.org" },
  { domain: "netflix.com" },
  { domain: "spotify.com" },
  { domain: "disneyplus.com" },
  { domain: "hulu.com" },
  { domain: "twitch.tv" },
  { domain: "dropbox.com" },
  { domain: "box.com" },
  { domain: "adobe.com" },
  { domain: "docusign.com" },
  { domain: "salesforce.com" },
  { domain: "slack.com" },
  { domain: "zoom.us" },
  { domain: "github.com" },
  { domain: "gitlab.com" },
  { domain: "atlassian.com" },
  { domain: "oracle.com" },
  { domain: "ibm.com" },
  { domain: "cloudflare.com" },
  { domain: "godaddy.com" },
  { domain: "namecheap.com" },
  { domain: "wordpress.com" },
  { domain: "shopify.com" },
  { domain: "okta.com" },
  { domain: "yahoo.com" },
  { domain: "steampowered.com" },
  { domain: "epicgames.com" },
  { domain: "roblox.com" },
  { domain: "playstation.com" },
  { domain: "nintendo.com" },

  // ── AI / LLM providers ────────────────────────────────────────────────
  // Impersonation targets for API-key harvesting and fake-console phishing.
  // The registrable domains here are the same ones `api-brands.ts` already pins
  // as legitimate; that tier keys on exact host TOKENS, so it never sees a
  // near-miss spelling of the domain itself (`0penai.com`, `anthropic.co`).
  { domain: "openai.com" },
  { domain: "anthropic.com" },
  { domain: "huggingface.co" },
  { domain: "mistral.ai" },
  { domain: "cohere.com" },

  // ── commerce / logistics / travel ─────────────────────────────────────
  { domain: "ebay.com" },
  { domain: "walmart.com" },
  { domain: "target.com" },
  { domain: "bestbuy.com" },
  { domain: "costco.com" },
  { domain: "etsy.com" },
  { domain: "aliexpress.com" },
  { domain: "alibaba.com" },
  { domain: "booking.com" },
  { domain: "airbnb.com" },
  { domain: "expedia.com" },
  { domain: "uber.com" },
  { domain: "lyft.com" },
  { domain: "dhl.com" },
  { domain: "fedex.com" },
  { domain: "ups.com" },
  { domain: "usps.com" },
  { domain: "royalmail.com" },
  { domain: "dpd.com" },
];

/**
 * Registrable brand domains on the watchlist, deduped. Consumed by the
 * domain-based brand detectors (`brand_lookalike`, `brand_homoglyph`,
 * `brand_soundsquat`, `brand_bitsquat`, `homograph_skeleton_collision`) for
 * edit-distance / fold / skeleton comparison.
 */
export const BRAND_DOMAINS: readonly string[] = [
  ...new Set(BRAND_WATCHLIST.map((b) => b.domain)),
];
