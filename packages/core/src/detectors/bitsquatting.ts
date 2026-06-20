import type { Detector, DetectorFinding } from "./types.js";
import { BRAND_DOMAINS } from "../data/brands.js";
import {
  BRAND_LABEL_SET,
  significantLabel,
  asciiRegistrableBrandCandidate,
} from "./brand-utils.js";

/**
 * T3 — `brand_bitsquat` (Epic G, IDEAS-ADDENDUM §4). SCORING, weight 0.15 (LOW).
 *
 * Detects BITSQUATTING: a host whose registrable LABEL is a SINGLE-BIT-FLIP
 * neighbor of a watchlist brand label — the memory/transmission-error attack
 * class. A cosmic ray, a flaky DIMM, or a bad network hop flips one bit of one
 * byte of a brand domain a client meant to resolve; an attacker who has
 * registered that one-bit-off domain silently receives the traffic. `netfliz.com`
 * (netfli**x** → netfli**z**: the byte `x`=0x78 with bit 1 flipped is `z`=0x7a)
 * is a bitsquat of `netflix`; `amazgn.com` (amaz**o**n → amaz**g**n) of `amazon`.
 *
 * ── How it works: precompute every brand's bit-flip neighborhood once ────────
 * For each watchlist brand label we enumerate the ~`len*8` candidates produced
 * by flipping one bit of one ASCII byte, keep only those whose flipped byte is
 * still a valid DNS label character (`a-z`, `0-9`, `-`), and record
 * neighbor→brand in a Set/Map built ONCE at module load. At runtime the input
 * label is an O(1) membership test — we never generate neighbors of the input.
 * The bit-flip enumeration is an intrinsic algorithm over the already-pinned
 * brand watchlist (like the ASCII-confusables fold or the soundsquat key), so it
 * carries NO `dataVersions` pin — there is no external/curated data here.
 *
 * ── Precision (SC-2, precision=1 discipline) ────────────────────────────────
 * A single bit flip is, by construction, also an edit-distance-1 neighbor, so
 * this detector OVERLAPS `brand_lookalike` on most inputs (they stack — distinct
 * codes). What `brand_bitsquat` adds is the *named attack class*: it identifies
 * specifically the memory-error subset and reports the exact byte/bit, which the
 * fuzzy edit-distance code cannot. It is deliberately conservative:
 *  - **Pure-ASCII registrable label only.** A non-ASCII (IDN) host belongs to the
 *    confusable / E3 detectors; the all-ASCII watchlist cannot be a byte-level
 *    bit-flip of a Unicode label.
 *  - **Exact brand never fires.** A watchlist brand domain, or an input label
 *    equal to a brand label, IS the brand — skip.
 *  - **Whole-label equality only.** The input label must equal a precomputed
 *    neighbor exactly; no substring / contains matching.
 *  - **Short-label guard (MIN_LABEL_LEN).** Short brands (`ups`, `dhl`, `box`,
 *    `ibm`, `n26`, `dpd`, `x`, `meta`, `visa`, `wise`, `cash`, `hsbc`) manufacture
 *    spurious 1-bit collisions, so a brand label shorter than MIN_LABEL_LEN
 *    contributes NO neighbors and a short input label is rejected.
 *  - **No-op flips excluded** (a neighbor must differ from the brand label) and a
 *    flip that lands on ANOTHER real watchlist brand label is dropped — we never
 *    fire when the bit-flip is itself a different genuine brand.
 *
 * Pure, synchronous, no network/fs — obeys every offline invariant.
 */

/** Min label length (input and brand) to allow a bitsquat match. */
const MIN_LABEL_LEN = 5;

/** Valid DNS label characters a flipped byte must remain within. */
const isLabelChar = (ch: string): boolean => /^[a-z0-9-]$/.test(ch);

/**
 * neighbor label → brand label. Built once: every valid single-bit-flip neighbor
 * of every watchlist brand label long enough to be safe, excluding no-op flips
 * and flips that land on another real brand label. The FIRST brand to claim a
 * given neighbor wins (deterministic by list order); collisions are vanishingly
 * rare on the current watchlist.
 */
const NEIGHBOR_TO_BRAND: ReadonlyMap<string, string> = (() => {
  const map = new Map<string, string>();
  for (const domain of BRAND_DOMAINS) {
    const label = significantLabel(domain).toLowerCase();
    if (label.length < MIN_LABEL_LEN) continue;
    for (let i = 0; i < label.length; i++) {
      const code = label.charCodeAt(i);
      for (let bit = 0; bit < 8; bit++) {
        const flipped = code ^ (1 << bit);
        if (flipped < 0 || flipped > 0x7f) continue; // stay in ASCII
        const ch = String.fromCharCode(flipped);
        if (!isLabelChar(ch)) continue; // discard non-label bytes
        const neighbor = label.slice(0, i) + ch + label.slice(i + 1);
        if (neighbor === label) continue; // no-op flip (bit already that value)
        if (BRAND_LABEL_SET.has(neighbor)) continue; // lands on another real brand
        if (!map.has(neighbor)) map.set(neighbor, label);
      }
    }
  }
  return map;
})();

export const bitsquatting: Detector = {
  id: "brand_bitsquat",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    // Pure-ASCII, non-IP registrable domain that is not itself a brand. Non-ASCII
    // (IDN) hosts belong to the confusable / E3 detectors; the real brand never
    // fires — it IS the brand.
    const raw = asciiRegistrableBrandCandidate(ctx);
    if (raw === null) return [];

    const label = significantLabel(raw);
    if (label.length < MIN_LABEL_LEN) return [];
    // An input label equal to a brand label is the brand spelling, not a bitsquat
    // of it (a brand on a different TLD is brand_lookalike's job).
    if (BRAND_LABEL_SET.has(label)) return [];

    const brand = NEIGHBOR_TO_BRAND.get(label);
    if (brand === undefined) return [];

    return [
      {
        code: "brand_bitsquat",
        detail:
          `registrable label '${label}' is a single-bit-flip neighbor of the ` +
          `known brand '${brand}' (a bitsquat — one flipped byte off the brand)`,
      },
    ];
  },
};
