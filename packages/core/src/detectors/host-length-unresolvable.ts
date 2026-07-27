import type { Detector } from "./types.js";

/** RFC 1035 §2.3.4 — a single DNS label is at most 63 octets. */
const MAX_LABEL_OCTETS = 63;
/** RFC 1035 §2.3.4 — the full domain name is at most 255 octets on the wire,
 *  which leaves 253 for the presentation-format hostname. */
const MAX_HOST_OCTETS = 253;

const octets = (s: string): number => new TextEncoder().encode(s).length;

/**
 * T2.7 revisited (`LINK-ygglwkuy`, `LINK-ibwuayzo` session). INFORMATIONAL,
 * weight 0.
 *
 * A hostname that exceeds a DNS length limit and therefore cannot resolve.
 *
 * **This is deliberately NOT a scoring finding, and the distinction is the whole
 * point.** Architecture §1.1 excludes "well-formed but unusable" from claim (a),
 * and host length is the worked case the section cites: a 64-octet label is
 * syntactically a hostname, is read identically by every parser, and simply fails.
 * Nothing is hidden and nobody disagrees. A scoring implementation of these caps
 * was written and reverted on exactly that reasoning.
 *
 * What changed is not the scope test but the **reporting** obligation: silently
 * returning `0.00` with no reasons tells the caller "nothing to say about this
 * URL", when in fact there is something definite and useful to say — it will
 * never resolve. So the check announces the fact at weight 0. It annotates
 * without raising severity, exactly like `normalization_delta` and
 * `confusable_in_path`, and a consumer that filters on score sees no change.
 *
 * The benign pin in `test/corpus/vectors.ts` still holds: the 64-character-label
 * vector stays `benign`, because a weight-0 reason does not move the score.
 *
 * Octets, not characters: DNS limits are byte limits, and they apply to the
 * A-label (ACE) form, which is what `ctx.host` carries.
 */
export const hostLengthUnresolvable: Detector = {
  id: "host_length_unresolvable",
  layer: "lexical",
  run(ctx) {
    // IP literals are not domain names and have no label structure.
    if (ctx.isIp || ctx.host === "") return [];

    const total = octets(ctx.host);
    // A trailing root dot is legal and does not count toward the 253.
    const effective = ctx.host.endsWith(".") ? total - 1 : total;

    const longLabels = ctx.hostLabels
      .map((label, i) => ({ label, i, n: octets(label) }))
      .filter(({ n }) => n > MAX_LABEL_OCTETS);

    const parts: string[] = [];
    if (longLabels.length > 0) {
      const named = longLabels
        .slice(0, 2)
        .map(({ i, n }) => `label ${i + 1} is ${n} octets`)
        .join(", ");
      const more = longLabels.length > 2 ? ` (+${longLabels.length - 2} more)` : "";
      parts.push(`${named}${more} — the limit is ${MAX_LABEL_OCTETS} (RFC 1035 §2.3.4)`);
    }
    if (effective > MAX_HOST_OCTETS) {
      parts.push(`the whole hostname is ${effective} octets — the limit is ${MAX_HOST_OCTETS}`);
    }
    if (parts.length === 0) return [];

    return [
      {
        code: "host_length_unresolvable",
        detail:
          `hostname exceeds a DNS length limit and cannot resolve: ${parts.join("; ")}. ` +
          `Informational only — every parser reads this host identically and nothing is ` +
          `disguised, so it is not a deception finding; it simply will not work`,
      },
    ];
  },
};
