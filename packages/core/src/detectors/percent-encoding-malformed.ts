import type { Detector, InspectionContext } from "./types.js";

/**
 * A `%` that is NOT followed by two hex digits. RFC 3986 §2.4 makes the
 * three-character `%HH` triplet the only meaning `%` has in a URI; anything
 * else is invalid, and the normative instruction is to reject rather than
 * repair, because repair is exactly where implementations diverge.
 *
 * Anchored, fixed-width, non-backtracking: a negative lookahead over a
 * two-character class. Stays inside the `inspect() < 5ms` budget.
 */
const MALFORMED_PERCENT = /%(?![0-9a-fA-F]{2})/g;

/** Components scanned, in the order they appear in the URI. */
const COMPONENTS = [
  ["userinfo", (ctx: InspectionContext) => ctx.userinfo],
  ["host", (ctx: InspectionContext) => ctx.rawHost],
  ["path", (ctx: InspectionContext) => ctx.path],
  ["query", (ctx: InspectionContext) => ctx.query],
  ["fragment", (ctx: InspectionContext) => ctx.fragment],
] as const;

/** Cap the detail string: the finding is "there is a bad escape", not a census. */
const MAX_TOKENS = 3;

/**
 * Render the offending escape as it appears, bounded to the `%` plus the two
 * characters that should have been hex. A trailing `%` renders as `%<end>` so
 * the detail is never an empty-looking `%`.
 */
function token(component: string, index: number): string {
  const tail = component.slice(index + 1, index + 3);
  return tail === "" ? "%<end>" : `%${tail}`;
}

/**
 * T2.14 — malformed percent-encoding (`LINK-woxuwnks`). Scoring, 0.2.
 *
 * This is claim (a) in its **false self-description** form (architecture §1.1,
 * form 3): `%` declares "the next two characters are a hex-encoded octet", and
 * in `%zz` — or in a bare `%` at the end of a path — the declaration does not
 * hold. It is the direct sibling of `punycode_malformed`, where `xn--` declares
 * "I am an ACE label" and does not decode, and it carries that code's weight
 * (0.2) for the same reason: a false self-description that every reader agrees
 * is false is anomalous, not an attack on its own.
 *
 * **Why `%zz` and a lone `%` are one code and one weight**, though the issue
 * asked whether to split them: the split it proposed tracked how uniformly
 * browsers tolerate the input, which is a fact about *reader agreement* —
 * §1.1 form 2. Form 2 is not what grounds this finding. Form 3 is, and both
 * inputs satisfy form 3 identically: `%` not followed by two hex digits is a
 * single defect in RFC 3986, which does not distinguish them either. Splitting
 * on tolerance would score the same false claim two different ways depending on
 * what parsers happen to do with it, which is the reasoning §1.1 rules out.
 *
 * Not a validity sweep: well-formed `%HH` is untouched at any nesting depth
 * (that is `encoding_obfuscation`'s job), and a percent-encoded octet the
 * parser itself produced — a space, a non-ASCII character — is by construction
 * well-formed and never fires.
 */
export const percentEncodingMalformed: Detector = {
  id: "percent_encoding_malformed",
  layer: "lexical",
  run(ctx) {
    const hits: string[] = [];
    let total = 0;

    for (const [name, get] of COMPONENTS) {
      const value = get(ctx);
      if (value === null || value === "" || !value.includes("%")) continue;

      for (const m of value.matchAll(MALFORMED_PERCENT)) {
        total += 1;
        if (hits.length < MAX_TOKENS) hits.push(`${token(value, m.index)} in ${name}`);
      }
    }

    if (total === 0) return [];
    const more = total > hits.length ? ` (+${total - hits.length} more)` : "";
    return [
      {
        code: "percent_encoding_malformed",
        detail:
          `malformed percent-encoding: ${hits.join(", ")}${more} — ` +
          `'%' is not followed by two hex digits (RFC 3986 §2.4), so the string ` +
          `declares an escape it does not carry`,
      },
    ];
  },
};
