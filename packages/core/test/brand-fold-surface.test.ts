/**
 * The brand fold surface: a review gate on watchlist additions (LINK-stnruoge).
 *
 * `LINK-tbqeqqvv` required "a test pinning the 192-label firing surface ... so
 * adding a brand to the watchlist cannot silently widen the surface without
 * review". It was never written, and PR #124 then did exactly what it was meant
 * to prevent: five brands took the surface 192 -> 197 with no record.
 *
 * This is that gate. Every entry below is a string that folds to a watchlist
 * brand through the letter-shaped ASCII digits (`0`->o, `1`->l, `5`->s), so
 * adding or removing a brand shows up here as explicit added or removed lines.
 * The membership lists are the point — a bare count would let one brand's labels
 * silently replace another's.
 *
 * The surface is derived BEHAVIORALLY, by running `inspect()` over every
 * candidate, not by reimplementing detector gates. A reimplementation would
 * drift from the detectors it claims to describe; a behavioral derivation
 * changes the moment shipped behavior changes, which is what a pinning test is
 * for.
 *
 * Candidates split into three groups, each pinned separately because they carry
 * different amounts of protection:
 *
 *   - ESCALATED (197) — `brand_homoglyph` + `ascii_homoglyph`, uniformly
 *     0.84/critical. The real structural surface.
 *   - HOMOGLYPH_ONLY (55) — `brand_homoglyph` alone, uniformly 0.80/high.
 *     These fail `ascii_homoglyph`'s stricter gates (leading digit, or digits
 *     outnumbering letters) but still fold to a brand under `brand_homoglyph`'s
 *     separate laxer gates. `0penai.com` is here. That gate asymmetry is the
 *     open Q3 sub-decision in `LINK-cphogucn`; this test only records it.
 *   - INERT (0) — empty since `LINK-lippdgpn`. Its one member was
 *     `turb0tax.intuit.com`: `turbotax.intuit.com` is on the watchlist as a
 *     subdomain, and the brand tier keyed ONLY on the registrable domain
 *     (`intuit.com`), so no fold of it could ever match. The hyphen/label token
 *     tier added by `LINK-lippdgpn` joins each host label's tokens against the
 *     brand LABEL set, which sees `turb0tax` -> `turbotax` directly. That is
 *     the payoff `LINK-scktwvio` kept the entry for. The group is retained (now
 *     asserted empty) because a future watchlist addition that fires nothing
 *     must still surface here rather than vanish.
 *
 * A note on the count: `LINK-stnruoge` computed 197 from the detector gates and
 * the live surface was 196 — the difference was exactly the one INERT entry,
 * i.e. the theoretical surface overcounted by the `LINK-scktwvio` defect. With
 * that defect fixed the two now agree at 197.
 *
 * INCLUSION CHARTER (the criterion this test exists to make measurable): a
 * brand earns its place by fold-reachability, not by name recognition. A brand
 * whose label contains no `o`, `l`, or `s` has NO pre-images and contributes
 * nothing to the structural tier — `huggingface` is the clearest example, and
 * `openai` contributes only the 0.80/high `0penai.com`. Such additions must be
 * justified on other grounds (or declined), never on brand fame alone. The
 * ZERO_FOLD_SURFACE_BRANDS list below names all 43 of them.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { BRAND_DOMAINS } from "../src/data/brands.js";
import {
  ASCII_DIGIT_HOMOGLYPHS,
  foldAsciiDigitHomoglyphs,
} from "../src/data/ascii-confusables.js";

/** Letter -> the digit that reads as it. The inverse of the shipped fold map. */
const LETTER_TO_DIGIT: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(ASCII_DIGIT_HOMOGLYPHS).map(([digit, letter]) => [letter, digit]),
);

interface Candidate {
  readonly brand: string;
  readonly label: string;
  readonly domain: string;
}

/**
 * Every distinct string that folds back to `brandDomain`'s significant label:
 * one per non-empty subset of its foldable letter positions. Each candidate is
 * checked against the shipped `foldAsciiDigitHomoglyphs`, so this enumeration
 * cannot silently disagree with the fold it is meant to invert.
 */
function foldPreimages(brandDomain: string): Candidate[] {
  const dot = brandDomain.indexOf(".");
  const label = dot === -1 ? brandDomain : brandDomain.slice(0, dot);
  const suffix = dot === -1 ? "" : brandDomain.slice(dot);

  const foldable = [...label].flatMap((ch, i) => (LETTER_TO_DIGIT[ch] ? [i] : []));
  const out: Candidate[] = [];
  for (let mask = 1; mask < 1 << foldable.length; mask++) {
    const chars = [...label];
    for (let bit = 0; bit < foldable.length; bit++) {
      if (mask & (1 << bit)) {
        const at = foldable[bit]!;
        chars[at] = LETTER_TO_DIGIT[label[at]!]!;
      }
    }
    const candidate = chars.join("");
    expect(foldAsciiDigitHomoglyphs(candidate)).toBe(label);
    out.push({ brand: brandDomain, label, domain: candidate + suffix });
  }
  return out;
}

function classify(): {
  escalated: Candidate[];
  homoglyphOnly: Candidate[];
  inert: Candidate[];
} {
  const escalated: Candidate[] = [];
  const homoglyphOnly: Candidate[] = [];
  const inert: Candidate[] = [];

  for (const brand of BRAND_DOMAINS) {
    for (const candidate of foldPreimages(brand)) {
      const codes = inspect(`https://${candidate.domain}`).reasons.map((r) => r.code);
      if (codes.includes("brand_homoglyph")) {
        if (codes.includes("ascii_homoglyph")) escalated.push(candidate);
        else homoglyphOnly.push(candidate);
      } else {
        inert.push(candidate);
      }
    }
  }
  return { escalated, homoglyphOnly, inert };
}

const surface = classify();
const domainsOf = (c: readonly Candidate[]): string[] => c.map((x) => x.domain).sort();

/**
 * The 0.84/critical structural surface. Adding a brand adds lines here;
 * removing one removes them. Either way it is reviewed, which is the whole
 * point.
 */
const ESCALATED_SURFACE: readonly string[] = [
  "a1ibaba.com",
  "a1iexpre55.com",
  "a1iexpre5s.com",
  "a1iexpres5.com",
  "a1iexpress.com",
  "ad0be.com",
  "aliexpre55.com",
  "aliexpre5s.com",
  "aliexpres5.com",
  "amaz0n.com",
  "americanexpre55.com",
  "americanexpre5s.com",
  "americanexpres5.com",
  "anthr0pic.com",
  "app1e.com",
  "at1a55ian.com",
  "at1a5sian.com",
  "at1as5ian.com",
  "at1assian.com",
  "atla55ian.com",
  "atla5sian.com",
  "atlas5ian.com",
  "b00king.com",
  "b0oking.com",
  "b10ckchain.com",
  "b1ockchain.com",
  "bank0famerica.com",
  "barc1ay5.co.uk",
  "barc1ays.co.uk",
  "barclay5.co.uk",
  "be5tbuy.com",
  "bl0ckchain.com",
  "bo0king.com",
  "c05tco.com",
  "c0here.com",
  "c0inba5e.com",
  "c0inbase.com",
  "c0stc0.com",
  "c0stco.com",
  "c10udf1are.com",
  "c10udflare.com",
  "c1oudf1are.com",
  "c1oudflare.com",
  "capita10ne.com",
  "capita1one.com",
  "capital0ne.com",
  "cha5e.com",
  "cl0udf1are.com",
  "cl0udflare.com",
  "cloudf1are.com",
  "co5tc0.com",
  "co5tco.com",
  "coinba5e.com",
  "costc0.com",
  "d0cu5ign.com",
  "d0cusign.com",
  "di5c0rd.com",
  "di5cord.com",
  "di5neyp1u5.com",
  "di5neyp1us.com",
  "di5neyplu5.com",
  "di5neyplus.com",
  "disc0rd.com",
  "disneyp1u5.com",
  "disneyp1us.com",
  "disneyplu5.com",
  "docu5ign.com",
  "dr0pb0x.com",
  "dr0pbox.com",
  "dropb0x.com",
  "epicgame5.com",
  "faceb00k.com",
  "faceb0ok.com",
  "facebo0k.com",
  "fide1ity.com",
  "g00gle.com",
  "g0daddy.com",
  "g0og1e.com",
  "g0ogle.com",
  "git1ab.com",
  "go0g1e.com",
  "go0gle.com",
  "goog1e.com",
  "in5tagram.com",
  "k1arna.com",
  "l10yd5bank.com",
  "l10ydsbank.com",
  "l1oyd5bank.com",
  "l1oydsbank.com",
  "ll0yd5bank.com",
  "ll0ydsbank.com",
  "lloyd5bank.com",
  "m0nz0.com",
  "m0nzo.com",
  "ma5tercard.com",
  "me55enger.com",
  "me5senger.com",
  "mes5enger.com",
  "metama5k.io",
  "mi5tra1.ai",
  "mi5tral.ai",
  "micr050ft.com",
  "micr05oft.com",
  "micr0s0ft.com",
  "micr0soft.com",
  "micro50ft.com",
  "micro5oft.com",
  "micros0ft.com",
  "mistra1.ai",
  "monz0.com",
  "natwe5t.com",
  "netf1ix.com",
  "nintend0.com",
  "orac1e.com",
  "p1ay5tati0n.com",
  "p1ay5tation.com",
  "p1aystati0n.com",
  "p1aystation.com",
  "paypa1.com",
  "pintere5t.com",
  "play5tati0n.com",
  "play5tation.com",
  "playstati0n.com",
  "r0b1ox.com",
  "r0binh00d.com",
  "r0binh0od.com",
  "r0binho0d.com",
  "r0binhood.com",
  "r0bl0x.com",
  "r0blox.com",
  "r0ya1mai1.com",
  "r0ya1mail.com",
  "r0yalmai1.com",
  "r0yalmail.com",
  "rev01ut.com",
  "rev0lut.com",
  "revo1ut.com",
  "rob10x.com",
  "rob1ox.com",
  "robinh00d.com",
  "robinh0od.com",
  "robinho0d.com",
  "robl0x.com",
  "roya1mai1.com",
  "roya1mail.com",
  "royalmai1.com",
  "s1ack.com",
  "sa1e5f0rce.com",
  "sa1e5force.com",
  "sa1esf0rce.com",
  "sa1esforce.com",
  "sale5f0rce.com",
  "sale5force.com",
  "salesf0rce.com",
  "sh0pify.com",
  "sp0tify.com",
  "steamp0wered.com",
  "te1egram.org",
  "tikt0k.com",
  "trez0r.io",
  // Reaches the escalated band via the hyphen/label token tier (LINK-lippdgpn),
  // not the registrable-domain tier — its registrable domain is `intuit.com`.
  "turb0tax.intuit.com",
  "u5bank.com",
  "venm0.com",
  "w0rdpre55.com",
  "w0rdpre5s.com",
  "w0rdpres5.com",
  "w0rdpress.com",
  "wa1mart.com",
  "we115farg0.com",
  "we115fargo.com",
  "we11sfarg0.com",
  "we11sfargo.com",
  "we1l5farg0.com",
  "we1l5fargo.com",
  "we1lsfarg0.com",
  "we1lsfargo.com",
  "we5ternuni0n.com",
  "we5ternunion.com",
  "wel15farg0.com",
  "wel15fargo.com",
  "wel1sfarg0.com",
  "wel1sfargo.com",
  "well5farg0.com",
  "well5fargo.com",
  "wellsfarg0.com",
  "westernuni0n.com",
  "what5app.com",
  "wordpre55.com",
  "wordpre5s.com",
  "wordpres5.com",
  "y0utube.com",
  "yah00.com",
  "yah0o.com",
  "yaho0.com",
  "ze11epay.com",
  "ze1lepay.com",
  "zel1epay.com",];

/**
 * Folds to a brand but misses `ascii_homoglyph`'s gates, so it lands 0.80/high
 * instead of 0.84/critical. Real coverage, weaker band — see `LINK-cphogucn` Q3.
 */
const HOMOGLYPH_ONLY_SURFACE: readonly string[] = [
  "0kta.com",
  "0penai.com",
  "0rac1e.com",
  "0racle.com",
  "110yd5bank.com",
  "110ydsbank.com",
  "11oyd5bank.com",
  "11oydsbank.com",
  "1edger.com",
  "1inkedin.com",
  "1ive.com",
  "1l0yd5bank.com",
  "1l0ydsbank.com",
  "1loyd5bank.com",
  "1loydsbank.com",
  "1yft.com",
  "51ack.com",
  "5a1e5f0rce.com",
  "5a1e5force.com",
  "5a1esf0rce.com",
  "5a1esforce.com",
  "5ale5f0rce.com",
  "5ale5force.com",
  "5alesf0rce.com",
  "5alesforce.com",
  "5antander.com",
  "5chwab.com",
  "5h0pify.com",
  "5hopify.com",
  "5lack.com",
  "5napchat.com",
  "5p0tify.com",
  "5potify.com",
  "5quareup.com",
  "5teamp0wered.com",
  "5teampowered.com",
  "5tripe.com",
  "b0x.com",
  "c05tc0.com",
  "ca5h.app",
  "dh1.com",
  "et5y.com",
  "g00g1e.com",
  "h5bc.com",
  "hu1u.com",
  "r0b10x.com",
  "u5p5.com",
  "u5ps.com",
  "up5.com",
  "usp5.com",
  "vi5a.com",
  "wi5e.com",
  "z00m.us",
  "z0om.us",
  "zo0m.us",];

/**
 * Fires nothing at all. EMPTY since `LINK-lippdgpn` closed `LINK-scktwvio` —
 * every fold pre-image of every watchlist brand now scores. Kept as an asserted
 * pin so a future addition that buys no coverage cannot land unnoticed.
 */
const INERT_CANDIDATES: readonly string[] = [];

/**
 * Watchlist labels with NO fold pre-image that reaches the escalated band. They
 * buy no structural coverage; every one of them needs a non-fold justification.
 */
const ZERO_FOLD_SURFACE_BRANDS: readonly string[] = [
  "airbnb",
  "binance",
  "box",
  "cash",
  "citibank",
  "dhl",
  "dpd",
  "ebay",
  "etsy",
  "expedia",
  "fedex",
  "github",
  "hsbc",
  "huggingface",
  "hulu",
  "ibm",
  "intuit",
  "kraken",
  "ledger",
  "linkedin",
  "live",
  "lyft",
  "meta",
  "n26",
  "namecheap",
  "okta",
  "openai",
  "reddit",
  "santander",
  "schwab",
  "snapchat",
  "squareup",
  "stripe",
  "target",
  "twitch",
  "uber",
  "ups",
  "usps",
  "vanguard",
  "visa",
  "wise",
  "x",
  "zoom",];

describe("brand fold surface — pinned review gate", () => {
  it("pins the exact escalated (0.84/critical) surface membership", () => {
    expect(domainsOf(surface.escalated)).toEqual([...ESCALATED_SURFACE].sort());
  });

  it("pins the exact homoglyph-only (0.80/high) surface membership", () => {
    expect(domainsOf(surface.homoglyphOnly)).toEqual([...HOMOGLYPH_ONLY_SURFACE].sort());
  });

  it("pins the inert candidates that fold to a brand but fire nothing", () => {
    expect(domainsOf(surface.inert)).toEqual([...INERT_CANDIDATES].sort());
  });

  it("pins the surface sizes, so a widening cannot pass as a reshuffle", () => {
    expect(surface.escalated).toHaveLength(197);
    expect(surface.homoglyphOnly).toHaveLength(55);
    expect(surface.inert).toHaveLength(0);
  });

  it("scores the escalated surface uniformly at 0.84/critical", () => {
    for (const candidate of surface.escalated) {
      const result = inspect(`https://${candidate.domain}`);
      expect(result.score, candidate.domain).toBeCloseTo(0.84, 5);
      expect(result.severity, candidate.domain).toBe("critical");
    }
  });

  it("scores the homoglyph-only surface uniformly at 0.80/high", () => {
    for (const candidate of surface.homoglyphOnly) {
      const result = inspect(`https://${candidate.domain}`);
      expect(result.score, candidate.domain).toBe(0.8);
      expect(result.severity, candidate.domain).toBe("high");
    }
  });

  it("names every brand that buys no escalated surface", () => {
    const reachable = new Set(surface.escalated.map((c) => c.label));
    const labels = BRAND_DOMAINS.map((d) => (d.includes(".") ? d.slice(0, d.indexOf(".")) : d));
    const zero = [...new Set(labels)].filter((l) => !reachable.has(l)).sort();
    expect(zero).toEqual([...ZERO_FOLD_SURFACE_BRANDS].sort());
  });

  it("keeps the fold-reachable brand count in step with the watchlist", () => {
    const reachable = new Set(surface.escalated.map((c) => c.label));
    expect(reachable.size).toBe(68);
    expect(new Set(BRAND_DOMAINS).size).toBe(111);
    expect(reachable.size + ZERO_FOLD_SURFACE_BRANDS.length).toBe(111);
  });

  it("records that the two AI brands added in PR #124 buy no escalated surface", () => {
    // Kept explicit because it is the evidence behind the inclusion charter:
    // 'huggingface' has no foldable letter at all, and 'openai' only reaches the
    // laxer homoglyph-only band via a leading digit.
    expect(ZERO_FOLD_SURFACE_BRANDS).toContain("huggingface");
    expect(ZERO_FOLD_SURFACE_BRANDS).toContain("openai");
    expect(HOMOGLYPH_ONLY_SURFACE).toContain("0penai.com");
    expect(foldPreimages("huggingface.co")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Prose coupling (LINK-sdtpvqsy).
//
// The counts above are also asserted in prose, in the canonical decision record
// — `docs/architecture.md` §6.1.1, inside an `— ADOPTED. … **Implemented**`
// block, and §6.1.3, where the surface size carries a live argument declining
// an external domain list. Nothing coupled the two, and the prose rotted: five
// watchlist additions moved the surface while the record kept stating the old
// figure in the present tense. The band pair rotted the same way, into source
// comments as well as tests, after the weights moved.
//
// Every expected string below is BUILT FROM `surface`, which is derived by
// running the shipped detectors. So the next watchlist or weight change fails
// here by name instead of desynchronising silently — the mechanical-guard
// pattern §6.4 already applies to `SCHEMA_VERSION`.
// ---------------------------------------------------------------------------

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SELF_PATH = fileURLToPath(import.meta.url);
const architectureDoc = readFileSync(join(REPO_ROOT, "docs", "architecture.md"), "utf8");

/**
 * Markdown hard-wraps, so matching a raw substring against a doc sentence
 * silently matches NOTHING the moment that sentence spans two lines — a guard
 * that passes by never testing anything. Flatten to a single line first.
 * Blockquote markers survive whitespace collapsing, so strip them per line
 * before joining.
 */
function flattenMarkdown(markdown: string): string {
  return markdown
    .split("\n")
    .map((line) => line.replace(/^\s*>\s?/, ""))
    .join(" ")
    .replace(/\s+/g, " ");
}

const architectureFlat = flattenMarkdown(architectureDoc);

/** The band a group actually lands in, formatted the way the prose writes it. */
function bandOf(candidates: readonly Candidate[]): { score: string; severity: string } {
  const first = candidates[0];
  expect(first, "band probe needs at least one member").toBeDefined();
  const result = inspect(`https://${first!.domain}`);
  return { score: result.score!.toFixed(2), severity: result.severity! };
}

const escalatedBand = bandOf(surface.escalated);
const homoglyphOnlyBand = bandOf(surface.homoglyphOnly);

describe("the prose is coupled to the derived surface (LINK-sdtpvqsy)", () => {
  it("architecture.md §6.1.1 states the live enumerated surface", () => {
    const reachable = new Set(surface.escalated.map((c) => c.label)).size;
    const watchlist = new Set(BRAND_DOMAINS).size;
    expect(architectureFlat).toContain(
      `today it is **${reachable} of ${watchlist}** brand labels, yielding ` +
        `**exactly ${surface.escalated.length} labels**`,
    );
  });

  it("architecture.md §6.1.3's external-list argument rests on the live surface size", () => {
    // The load-bearing half: the comparison against the 30,906-string surface a
    // CrUX import would produce. Asserted together so a correction to one
    // number cannot leave the other stranded.
    expect(architectureFlat).toContain(
      `its surface is ${surface.escalated.length} strings and therefore ` +
        "exhaustively probable. At 30,906 that argument does not exist.",
    );
  });

  it("architecture.md §6.1.1 states the live band pair for leading-digit folds", () => {
    expect(architectureFlat).toContain(
      `at \`${homoglyphOnlyBand.score}\`/\`${homoglyphOnlyBand.severity}\` rather than ` +
        `\`${escalatedBand.score}\`/\`${escalatedBand.severity}\``,
    );
  });

  it("no source comment describing this surface states a band it does not score", () => {
    // `brand-homoglyph.ts` and `brands.ts` both narrate this surface's bands in
    // prose, and both went stale when the weights moved. Any `<score>/<band>`
    // pair they state — or this file states — must be one the live pipeline
    // produces: the two surface bands, or the low band a digit-bearing label
    // that folds to gibberish gets.
    const gibberish = inspect("https://pete1.github.io/");
    const live = new Set([
      `${escalatedBand.score}/${escalatedBand.severity}`,
      `${homoglyphOnlyBand.score}/${homoglyphOnlyBand.severity}`,
      `${gibberish.score!.toFixed(2)}/${gibberish.severity!}`,
    ]);

    const sources = [
      join(REPO_ROOT, "packages", "core", "src", "detectors", "brand-homoglyph.ts"),
      join(REPO_ROOT, "packages", "core", "src", "data", "brands.ts"),
      SELF_PATH,
    ];
    const stale = sources.flatMap((path) => {
      const text = readFileSync(path, "utf8");
      return [...text.matchAll(/\b\d\.\d{2}\/(?:low|medium|high|critical)\b/g)]
        .map((m) => m[0])
        .filter((pair) => !live.has(pair))
        .map((pair) => `${path.slice(REPO_ROOT.length + 1)}: ${pair}`);
    });
    expect(stale).toEqual([]);
  });
});
