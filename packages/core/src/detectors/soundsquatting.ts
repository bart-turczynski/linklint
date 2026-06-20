import type { Detector, DetectorFinding } from "./types.js";
import { BRAND_DOMAINS } from "../data/brands.js";
import {
  BRAND_LABEL_SET,
  significantLabel,
  asciiRegistrableBrandCandidate,
} from "./brand-utils.js";

/**
 * T2 — `brand_soundsquat` (Epic G, IDEAS-ADDENDUM §4). SCORING, weight 0.3.
 *
 * Detects SOUNDSQUATTING: a host whose registrable label is a PHONETIC
 * homophone of a watchlist brand — it *sounds* like the brand when read aloud,
 * even though it is neither an edit-distance near-miss nor a digit/confusable
 * fold. `netflicks.com` (→ netflix), `dropboks.com` (→ dropbox),
 * `spotifi.com` (→ spotify). Per Addendum §4 these read as the brand to a human
 * ear/eye but are invisible to the G2 edit-distance and digit/skeleton folds:
 * `ck`→`k` plus `x`→`ks` is two raw edits over a 7-char label, below G2's
 * distance-2 length gate, so `netflicks` and `dropboks` currently flag NOTHING.
 * This detector fills exactly that recall hole.
 *
 * ── How it works: a deterministic, offline phonetic key ─────────────────────
 * Both the input label and each brand label are normalized to a small phonetic
 * key via an ordered, static substitution map of homophone digraphs/phonemes
 * (`ph`→`f`, `ck`→`k`, `x`→`ks`, `oo`→`u`, `y`→`i`, `z`→`s`, hard `c`/`ch`→`k`,
 * silent `gh`→``, …) followed by collapsing runs of a repeated letter
 * (`paypall`→`paypal`). Two strings with the SAME key are homophones. We fire
 * only on WHOLE-LABEL phonetic-key EQUALITY against a brand — never a loose
 * substring — which is the high-precision signal (the SC-2 discipline shared by
 * the whole brand family).
 *
 * The substitution map is a static micro-lexicon — an intrinsic property of how
 * English/keyboard homophones read, like `ascii-confusables.ts` (which digits
 * look like which letters) or the `bait_tokens` word list — so it carries NO
 * `dataVersions` pin (it is not external/curated data that evolves like the
 * brand watchlist).
 *
 * ── Precision (SC-2, precision=1 discipline) — phonetic matching is FP-prone ─
 * Phonetic keys are lossy, so this detector is deliberately conservative:
 *  - **Pure-ASCII registrable label only.** A non-ASCII host belongs to the
 *    confusable / E3 `homograph_skeleton_collision` detectors; the all-ASCII
 *    watchlist cannot be a genuine homophone of a Unicode label.
 *  - **Exact brand never fires.** If the input's registrable domain is itself a
 *    watchlist brand domain, it IS the brand — skip. An input label equal to a
 *    brand label is likewise skipped.
 *  - **Short-label guard.** Both the input label and the matched brand label,
 *    AND the resulting phonetic key, must be at least MIN_LABEL_LEN characters.
 *    This keeps short, key-degenerate brands (`x`, `ups`, `dhl`, `ibm`, `n26`,
 *    `hsbc`, `dpd`, `wise`, `box`, `meta`, `visa`, `cash`) from ever colliding —
 *    short keys are where phonetic folding manufactures spurious matches.
 *  - **Whole-label equality only** — the key of the input label must equal the
 *    key of a brand label exactly; no substring / contains matching.
 *
 * Pure, synchronous, no network/fs — obeys every offline invariant.
 */

/** Min length (label and phonetic key) to allow a soundsquat match. */
const MIN_LABEL_LEN = 5;

/**
 * Ordered homophone substitutions applied to build a phonetic key. ORDER
 * MATTERS: multi-char digraphs are folded before the single-char rules they
 * contain (e.g. `ck`/`ch` before bare `c`, `tch` before `ch`). Each entry is a
 * (pattern, replacement) homophone equivalence — the letters/clusters on the
 * left all *sound the same as* the right when a domain label is read aloud.
 */
const HOMOPHONE_SUBSTITUTIONS: ReadonlyArray<readonly [string, string]> = [
  // ── multi-char digraphs / clusters first ──────────────────────────────
  ["sch", "sk"], // schwab → skwab
  ["tch", "ch"], // twitch → twich (then ch → k below)
  ["ph", "f"], // -ph- → f
  ["ck", "k"], // netflicks → netfliks-ish; dropbo-ck → k
  ["qu", "kw"], // square → skware
  ["wr", "r"], // silent w
  ["wh", "w"], // whatsapp → watsapp
  ["kn", "n"], // silent k
  ["gh", ""], // silent gh
  // ── single-char phoneme folds ─────────────────────────────────────────
  ["x", "ks"], // netfli-x ↔ netfli-cks; dropbo-x ↔ dropbo-ks
  ["oo", "u"], // -oo- → u (robinhood → robinhud)
  ["ou", "u"], // -ou- → u
  ["ew", "u"], // -ew- → u
  ["ie", "i"],
  ["ee", "i"],
  ["ea", "i"],
  ["ai", "a"],
  ["ay", "a"],
  ["ch", "k"], // hard ch → k (chase → khase)
  ["c", "k"], // hard c → k (coinbase → koinbase)
  ["z", "s"], // z ↔ s (trezor → tresor)
  ["y", "i"], // -y vowel → i (spotify → spotifi)
];

/** Normalize a label to its phonetic key (lowercased, folded, doubles collapsed). */
function phoneticKey(label: string): string {
  let key = label.toLowerCase();
  for (const [pattern, replacement] of HOMOPHONE_SUBSTITUTIONS) {
    key = key.split(pattern).join(replacement);
  }
  // Collapse runs of a repeated letter: paypall → paypal, githubb → github.
  key = key.replace(/(.)\1+/g, "$1");
  return key;
}

/**
 * Phonetic key → brand label, for labels and keys long enough to be safe. Built
 * once. Only the FIRST brand for a given key is kept (deterministic by list
 * order); a key collision among real brands does not occur on the current
 * watchlist, but if it did the detail would simply name one of them.
 */
const BRAND_KEY_TO_LABEL: ReadonlyMap<string, string> = (() => {
  const map = new Map<string, string>();
  for (const domain of BRAND_DOMAINS) {
    const label = significantLabel(domain);
    if (label.length < MIN_LABEL_LEN) continue;
    const key = phoneticKey(label);
    if (key.length < MIN_LABEL_LEN) continue;
    if (!map.has(key)) map.set(key, label);
  }
  return map;
})();

export const soundsquatting: Detector = {
  id: "brand_soundsquat",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    // Pure-ASCII, non-IP registrable domain that is not itself a brand. Non-ASCII
    // (IDN) hosts belong to the confusable / E3 detectors; the real brand never
    // fires — it IS the brand.
    const raw = asciiRegistrableBrandCandidate(ctx);
    if (raw === null) return [];

    const label = significantLabel(raw);
    if (label.length < MIN_LABEL_LEN) return [];
    // An input label equal to a brand label is the brand spelling, not a
    // homophone of it — skip (e.g. a brand on a different TLD is G2's job).
    if (BRAND_LABEL_SET.has(label)) return [];

    const key = phoneticKey(label);
    if (key.length < MIN_LABEL_LEN) return [];

    const brand = BRAND_KEY_TO_LABEL.get(key);
    if (brand === undefined) return [];

    return [
      {
        code: "brand_soundsquat",
        detail:
          `registrable label '${label}' is a phonetic homophone of the known ` +
          `brand '${brand}' (both reduce to the sound key '${key}') — a soundsquat`,
      },
    ];
  },
};
