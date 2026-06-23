import type { Detector, DetectorFinding } from "./types.js";
import { toUnicode, hasMalformedPunycode } from "../unicode/idna.js";

/**
 * `idn_host` (scoring, weight 0.7 → high). The registrable domain is an
 * internationalized domain name (it carries a non-ASCII label, whether written
 * in Unicode `münchen.de` or punycode `xn--mnchen-3ya.de`). For a Western-market
 * audience a Unicode/punycode domain is almost always accidental, so it is
 * **blocked by default** (`idnPolicy: "block"`): the weight lands the verdict at
 * `high`, enough to fail the default `--fail-on high` gate, while `critical`
 * stays reserved for the unambiguous homograph/script attacks.
 *
 * ── Gating (read from the normalized runtime config) ─────────────────────────
 * - `idnPolicy: "allow"` suppresses the signal entirely (the historical,
 *   IDN-agnostic verdict) — for deployments that legitimately serve IDNs.
 * - `idnAllowlist` exempts specific registrable domains even under `"block"`.
 *
 * ── Scope & precision ───────────────────────────────────────────────────────
 * - Scoped to the **registrable domain** (eTLD+1), canonicalized to its Unicode
 *   form so punycode and Unicode presentations are treated identically and the
 *   allow-list matches either. An ASCII registrable domain with, say, a Unicode
 *   *path* never fires (that is `confusable_in_path`'s territory).
 * - The dangerous IDN subset (script-mixing, all-Latin-confusable homographs) is
 *   already `critical` via `mixed_script` / `homograph_latin_skeleton`
 *   regardless of this option; `idn_host` adds the high-severity block for the
 *   remaining *genuine* IDNs and simply stacks on the dangerous ones.
 * - IP / hostless inputs have no registrable domain and never fire.
 *
 * Pure, synchronous, no network/fs — obeys every offline invariant.
 */

/** True when `s` contains any non-ASCII codepoint. */
function hasNonAscii(s: string): boolean {
  return !/^[\x00-\x7f]*$/.test(s);
}

export const idnHost: Detector = {
  id: "idn_host",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.runtime.idnPolicy === "allow") return [];
    const rd = ctx.registrableDomainLower;
    if (!rd || ctx.isIp) return [];
    // A malformed xn-- label is a BROKEN IDN owned by punycode_malformed — not a
    // genuine internationalized domain. Skip so the two never double-flag.
    if (hasMalformedPunycode(ctx.host)) return [];

    // Canonical Unicode form: decodes a punycode (xn--) registrable domain so the
    // IDN test and the allow-list comparison are presentation-independent.
    const rdUnicode = toUnicode(rd).toLowerCase();
    if (!hasNonAscii(rdUnicode)) return [];
    if (ctx.runtime.idnAllowlist.has(rdUnicode)) return [];

    return [
      {
        code: "idn_host",
        detail:
          `registrable domain '${ctx.registrableDomain}' is an internationalized ` +
          `(non-ASCII) domain '${rdUnicode}' — blocked by default (idnPolicy 'block'); ` +
          "set idnPolicy 'allow' or add it to idnAllowlist to permit",
      },
    ];
  },
};
