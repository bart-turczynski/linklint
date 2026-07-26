import type { Detector, DetectorFinding } from "./types.js";
import { BRAND_DOMAINS } from "../data/brands.js";
import { skeleton } from "../unicode/skeleton.js";
import { toUnicode } from "../unicode/idna.js";

/**
 * `homograph_skeleton_collision` (scoring). The single documented v1
 * *detection* hole that FR-D-16 deferred: a single-script, all-confusable
 * look-alike of a brand. An all-Cyrillic `сһаѕе.com` (every letter a Cyrillic
 * homoglyph of the Latin one) has NO script mixing, so `mixed_script` never
 * fires, and confusable annotation is weight-0 — yet it reads as `chase.com`
 * to a human. This detector scores exactly that case.
 *
 * ── How it works ───────────────────────────────────────────────────────────
 * Compute the UTS#39 `skeleton()` (unicode/skeleton.ts) of the registrable
 * domain and collide it against the skeleton of each watchlist brand domain.
 * The brand domains are all-ASCII, so their skeleton is effectively themselves;
 * a collision means "this Unicode host skeletonizes to a real brand". An EXACT
 * whole-domain skeleton match is the decisive, high-precision signal — we never
 * score raw confusables (the SC-2 failure mode that deferred FR-D-16); we only
 * fire when the skeleton lands on a brand byte-for-byte.
 *
 * ── No double-fire with `brand_homoglyph` ───────────────────────────────
 * `brand_homoglyph` owns the PURE-ASCII digit-fold case (`paypa1.com` → `paypal.com`) and
 * bails on any non-ASCII registrable domain. This detector is its mirror: it
 * runs ONLY when the registrable domain is non-ASCII (carries a codepoint
 * > U+007F). That single guard makes the two mutually exclusive by
 * construction — an ASCII digit-fold input can never reach here, so it stays
 * `brand_homoglyph`'s. (Conversely `brand_homoglyph` already skips non-ASCII, so this fills exactly its gap.)
 *
 * ── No double-fire with `idna_mapping_ambiguity` ────────────────────────
 * A compatibility homograph — fullwidth Latin `ｇｏｏｇｌｅ.com` — NFKC-folds to
 * pure ASCII (`google.com`) and is already owned by the
 * `idna_mapping_ambiguity` annotation (resolver disagreement). This detector
 * therefore additionally requires the host to still carry a non-ASCII codepoint
 * AFTER NFKC: that excludes the compatibility-fold family and keeps this detector on its
 * documented target — a genuine cross-script (e.g. all-Cyrillic) homograph.
 *
 * ── Precision (SC-2, precision=1 discipline) ───────────────────────────────
 * - Exact brand: a real brand domain is all-ASCII, so it is guarded out before
 *   any collision test — it can never fire.
 * - Legitimate single-script IDNs (`пример.com`) skeletonize to a non-brand
 *   string (`pprimer.com`) and do not collide with any watchlist brand.
 * - Only an exact whole-domain skeleton == brand match fires.
 *
 * Pure, synchronous, no network/fs — obeys every offline invariant.
 */

/** Brand-domain skeletons, precomputed once for O(1) collision membership. */
const BRAND_SKELETONS: ReadonlyMap<string, string> = new Map(
  BRAND_DOMAINS.map((brand) => [skeleton(brand), brand]),
);

/** True when `s` contains any non-ASCII codepoint (i.e. is an IDN/Unicode host). */
function hasNonAscii(s: string): boolean {
  return !/^[\x00-\x7f]*$/.test(s);
}

export const skeletonCollision: Detector = {
  id: "homograph_skeleton_collision",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    const input = ctx.registrableDomain;
    if (!input || ctx.isIp) return [];
    // Canonical Unicode form first — see latin-skeleton-homograph.ts: a punycode
    // (xn--) registrable domain is pure ASCII as written and would otherwise slip
    // past the non-ASCII guard below, letting the same brand homograph score
    // differently depending on how it was spelled.
    const host = toUnicode(input.toLowerCase());
    // Non-ASCII only: the pure-ASCII digit-fold case belongs to
    // brand_homoglyph. This guard makes the two detectors mutually exclusive.
    if (!hasNonAscii(host)) return [];
    // Skip the compatibility-fold family (fullwidth/halfwidth Latin etc.): if the
    // host NFKC-folds to pure ASCII it is an IDNA-mapping homograph already owned
    // by idna_mapping_ambiguity, not the cross-script case this detector targets.
    if (!hasNonAscii(host.normalize("NFKC"))) return [];

    const skel = skeleton(host);
    const brand = BRAND_SKELETONS.get(skel);
    if (brand === undefined) return [];

    // See latin-skeleton-homograph.ts: show the decoded form for punycode input.
    const shown =
      host === input.toLowerCase() ? `'${input}'` : `'${input}' (Unicode form '${host}')`;

    return [
      {
        code: "homograph_skeleton_collision",
        detail:
          `registrable domain ${shown} has the same UTS#39 confusable ` +
          `skeleton ('${skel}') as the known brand '${brand}' — a single-script ` +
          "whole-label homograph",
      },
    ];
  },
};
