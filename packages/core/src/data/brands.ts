/**
 * Curated brand watchlist. The shared, authoritative data source all
 * brand detectors consume:
 *   - the **registrable brand domain** (`paypal.com`) feeds the
 *     `brand_lookalike` detector's Damerau-Levenshtein distance against an
 *     input's registrable domain, and
 *   - one or more **brand keyword(s)** (`paypal`) feed combosquatting /
 *     `brand_in_path`-style checks.
 *
 * High-abuse impersonation targets only — banks, big tech, payment processors,
 * major commerce/logistics, and a few perennial phishing favourites. Kept
 * deliberately conservative (~50–200 entries): every keyword widens what
 * `brand_in_path` can fire on, so precision comes first (SC-2).
 *
 * Entries are normalized: lowercase domain (registrable, no scheme/path/www),
 * lowercase keywords. `BRAND_KEYWORDS` (the `brand_in_path` contract) is
 * DERIVED from this list — one source of truth.
 *
 * Version-pinned via dataVersions.brands. Plain module exports under src/data/,
 * consumed via static import — same tree-shakeable pattern as risky-tlds.ts /
 * confusables.ts.
 */

/** A single brand on the watchlist. */
export interface BrandEntry {
  /** Registrable brand domain, lowercase (e.g. `paypal.com`). */
  readonly domain: string;
  /**
   * Brand keyword(s), lowercase, used for combosquatting / brand-in-path. May
   * be empty when the brand's only natural keyword is a generic English word
   * (e.g. `meta`, `box`, `target`) that would over-flag — the domain still
   * participates in lookalike matching via `BRAND_DOMAINS`.
   */
  readonly keywords: readonly string[];
}

/**
 * The watchlist. Order is not significant. Keep entries lowercase; keywords are
 * bare brand tokens (no TLD, no separators) that read as a single path segment.
 */
export const BRAND_WATCHLIST: readonly BrandEntry[] = [
  // ── payments / finance ────────────────────────────────────────────────
  { domain: "paypal.com", keywords: ["paypal"] },
  { domain: "stripe.com", keywords: ["stripe"] },
  { domain: "venmo.com", keywords: ["venmo"] },
  { domain: "wise.com", keywords: ["transferwise"] },
  { domain: "squareup.com", keywords: ["squareup"] },
  { domain: "cash.app", keywords: ["cashapp"] },
  { domain: "coinbase.com", keywords: ["coinbase"] },
  { domain: "binance.com", keywords: ["binance"] },
  { domain: "kraken.com", keywords: ["kraken"] },
  { domain: "blockchain.com", keywords: ["blockchain"] },
  { domain: "metamask.io", keywords: ["metamask"] },
  { domain: "ledger.com", keywords: ["ledger"] },
  { domain: "trezor.io", keywords: ["trezor"] },
  { domain: "chase.com", keywords: ["chase"] },
  { domain: "wellsfargo.com", keywords: ["wellsfargo"] },
  { domain: "bankofamerica.com", keywords: ["bankofamerica"] },
  { domain: "citibank.com", keywords: ["citibank", "citi"] },
  { domain: "capitalone.com", keywords: ["capitalone"] },
  { domain: "usbank.com", keywords: ["usbank"] },
  { domain: "barclays.co.uk", keywords: ["barclays"] },
  { domain: "hsbc.com", keywords: ["hsbc"] },
  { domain: "lloydsbank.com", keywords: ["lloydsbank", "lloyds"] },
  { domain: "natwest.com", keywords: ["natwest"] },
  { domain: "santander.com", keywords: ["santander"] },
  { domain: "revolut.com", keywords: ["revolut"] },
  { domain: "monzo.com", keywords: ["monzo"] },
  { domain: "n26.com", keywords: ["n26"] },
  { domain: "americanexpress.com", keywords: ["americanexpress", "amex"] },
  { domain: "mastercard.com", keywords: ["mastercard"] },
  { domain: "visa.com", keywords: ["visa"] },
  { domain: "westernunion.com", keywords: ["westernunion"] },
  { domain: "fidelity.com", keywords: ["fidelity"] },
  { domain: "schwab.com", keywords: ["schwab"] },
  { domain: "vanguard.com", keywords: ["vanguard"] },
  { domain: "robinhood.com", keywords: ["robinhood"] },
  { domain: "intuit.com", keywords: ["intuit"] },
  { domain: "turbotax.intuit.com", keywords: ["turbotax"] },
  { domain: "klarna.com", keywords: ["klarna"] },
  { domain: "zellepay.com", keywords: ["zelle"] },

  // ── big tech / platforms / identity ───────────────────────────────────
  { domain: "google.com", keywords: ["google", "gmail"] },
  { domain: "youtube.com", keywords: ["youtube"] },
  { domain: "apple.com", keywords: ["apple", "icloud", "itunes"] },
  { domain: "microsoft.com", keywords: ["microsoft", "outlook", "office365", "onedrive"] },
  { domain: "live.com", keywords: ["hotmail"] },
  { domain: "amazon.com", keywords: ["amazon"] },
  // meta.com keyword `meta` omitted — generic English word, would over-flag
  { domain: "meta.com", keywords: [] },
  { domain: "facebook.com", keywords: ["facebook"] },
  { domain: "instagram.com", keywords: ["instagram"] },
  { domain: "whatsapp.com", keywords: ["whatsapp"] },
  { domain: "messenger.com", keywords: ["messenger"] },
  { domain: "x.com", keywords: ["twitter"] },
  { domain: "linkedin.com", keywords: ["linkedin"] },
  { domain: "tiktok.com", keywords: ["tiktok"] },
  { domain: "snapchat.com", keywords: ["snapchat"] },
  { domain: "pinterest.com", keywords: ["pinterest"] },
  { domain: "reddit.com", keywords: ["reddit"] },
  { domain: "discord.com", keywords: ["discord"] },
  { domain: "telegram.org", keywords: ["telegram"] },
  { domain: "netflix.com", keywords: ["netflix"] },
  { domain: "spotify.com", keywords: ["spotify"] },
  { domain: "disneyplus.com", keywords: ["disneyplus"] },
  { domain: "hulu.com", keywords: ["hulu"] },
  { domain: "twitch.tv", keywords: ["twitch"] },
  { domain: "dropbox.com", keywords: ["dropbox"] },
  // box.com keyword `box` omitted — generic English word
  { domain: "box.com", keywords: [] },
  { domain: "adobe.com", keywords: ["adobe"] },
  { domain: "docusign.com", keywords: ["docusign"] },
  { domain: "salesforce.com", keywords: ["salesforce"] },
  { domain: "slack.com", keywords: ["slack"] },
  { domain: "zoom.us", keywords: ["zoom"] },
  { domain: "github.com", keywords: ["github"] },
  { domain: "gitlab.com", keywords: ["gitlab"] },
  { domain: "atlassian.com", keywords: ["atlassian"] },
  { domain: "oracle.com", keywords: ["oracle"] },
  { domain: "ibm.com", keywords: ["ibm"] },
  { domain: "cloudflare.com", keywords: ["cloudflare"] },
  { domain: "godaddy.com", keywords: ["godaddy"] },
  { domain: "namecheap.com", keywords: ["namecheap"] },
  { domain: "wordpress.com", keywords: ["wordpress"] },
  { domain: "shopify.com", keywords: ["shopify"] },
  { domain: "okta.com", keywords: ["okta"] },
  { domain: "yahoo.com", keywords: ["yahoo"] },
  { domain: "steampowered.com", keywords: ["steam"] },
  { domain: "epicgames.com", keywords: ["epicgames"] },
  { domain: "roblox.com", keywords: ["roblox"] },
  { domain: "playstation.com", keywords: ["playstation"] },
  { domain: "nintendo.com", keywords: ["nintendo"] },

  // ── commerce / logistics / travel ─────────────────────────────────────
  { domain: "ebay.com", keywords: ["ebay"] },
  { domain: "walmart.com", keywords: ["walmart"] },
  // target.com keyword `target` omitted — generic English word
  { domain: "target.com", keywords: [] },
  { domain: "bestbuy.com", keywords: ["bestbuy"] },
  { domain: "costco.com", keywords: ["costco"] },
  { domain: "etsy.com", keywords: ["etsy"] },
  { domain: "aliexpress.com", keywords: ["aliexpress"] },
  { domain: "alibaba.com", keywords: ["alibaba"] },
  // booking.com keyword `booking` omitted — generic English word
  { domain: "booking.com", keywords: [] },
  { domain: "airbnb.com", keywords: ["airbnb"] },
  { domain: "expedia.com", keywords: ["expedia"] },
  { domain: "uber.com", keywords: ["uber"] },
  { domain: "lyft.com", keywords: ["lyft"] },
  { domain: "dhl.com", keywords: ["dhl"] },
  { domain: "fedex.com", keywords: ["fedex"] },
  { domain: "ups.com", keywords: ["ups"] },
  { domain: "usps.com", keywords: ["usps"] },
  { domain: "royalmail.com", keywords: ["royalmail"] },
  { domain: "dpd.com", keywords: ["dpd"] },
];

/**
 * All watchlist keywords, deduped. This IS the `brand_in_path` contract:
 * a `ReadonlySet<string>` of lowercase brand keywords. Derived from
 * `BRAND_WATCHLIST` so the watchlist is the single source of truth.
 */
export const BRAND_KEYWORDS: ReadonlySet<string> = new Set(
  BRAND_WATCHLIST.flatMap((b) => b.keywords),
);

/** Returns true if `token` (case-insensitively) is a watchlist brand keyword. */
export function isBrandKeyword(token: string): boolean {
  return BRAND_KEYWORDS.has(token.toLowerCase());
}

/**
 * Registrable brand domains on the watchlist, deduped. Consumed by the
 * `brand_lookalike` detector for edit-distance comparison.
 */
export const BRAND_DOMAINS: readonly string[] = [
  ...new Set(BRAND_WATCHLIST.map((b) => b.domain)),
];
