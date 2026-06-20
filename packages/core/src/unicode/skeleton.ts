import { CONFUSABLES } from "../data/confusables.js";

/**
 * UTS#39 §4 `skeleton(X)` — the confusable skeleton of a string (E3 / FR-D-16
 * follow-up). Two strings are *visually confusable* exactly when their
 * skeletons are equal, so a skeleton collision against a known brand is a
 * whole-label homograph of that brand.
 *
 * Algorithm (per UTS#39 "Confusable Detection", definition of skeleton):
 *   1. Apply NFD to X.
 *   2. Replace each codepoint with its confusable prototype from the UTS#39
 *      confusables table, applied repeatedly until a fixpoint (a prototype may
 *      itself contain a confusable).
 *   3. Apply NFD again to the result.
 *
 * Data source is the repo's existing confusables table (`data/confusables.ts`,
 * generated from the official UTS#39 `confusables.txt` and version-pinned via
 * `dataVersions.unicodeConfusables`). We invent NO new data and fetch nothing.
 * Because that curated table's targets are all ASCII, one substitution pass
 * already reaches a fixpoint for real inputs; the loop is kept (bounded) so the
 * UTS#39 fixpoint contract holds even if the table is later widened.
 *
 * Pure, synchronous, never throws — safe inside the offline `inspect()` path.
 */

/** Bound on the fixpoint loop — a guard against a pathological cyclic table. */
const MAX_PASSES = 8;

/** Map each codepoint of `s` through the confusables table (single pass). */
function mapPass(s: string): string {
  let out = "";
  for (const ch of s) {
    const hit = CONFUSABLES.get(ch);
    out += hit ? hit.target : ch;
  }
  return out;
}

/**
 * Return the UTS#39 confusable skeleton of `s`. Equal skeletons ⇒ the two
 * strings are visually confusable.
 */
export function skeleton(s: string): string {
  // (1) NFD.
  let current = s.normalize("NFD");
  // (2) Substitute to a fixpoint.
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    const next = mapPass(current);
    if (next === current) break;
    current = next;
  }
  // (3) NFD again.
  return current.normalize("NFD");
}
