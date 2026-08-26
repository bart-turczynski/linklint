import type { Detector, InspectionContext } from "./types.js";

/**
 * ASCII bytes that are dangerous to *materialize* mid-URL, keyed by low byte.
 *
 * Two groups, both structural:
 *   - **Whitespace / control** — a CR or LF lets a requester smuggle a second
 *     protocol on the wire or inject a header; TAB and SPACE terminate a host so
 *     validator and resolver disagree; NUL truncates for a C-string resolver.
 *   - **URI delimiters** — a `/`, `:`, `@`, `?` or `#` that appears where the
 *     original string had none re-parses the URL: `@` moves the authority, `/`
 *     ends it, `:` forges a port.
 */
const DANGEROUS_LOW_BYTE = new Map<number, string>([
  [0x00, "NUL — truncates the string for a C-string resolver"],
  [0x09, "TAB — terminates the host so validator and resolver disagree"],
  [0x0a, "LF — injects a header / smuggles a second protocol"],
  [0x0b, "VT — whitespace a lenient parser strips"],
  [0x0c, "FF — whitespace a lenient parser strips"],
  [0x0d, "CR — injects a header / smuggles a second protocol"],
  [0x20, "SPACE — terminates the host for getaddrinfo"],
  [0x23, "'#' — starts a fragment, discarding the rest"],
  [0x2f, "'/' — ends the authority"],
  [0x3a, "':' — forges a port separator"],
  [0x3f, "'?' — starts a query, discarding the rest"],
  [0x40, "'@' — moves the authority, so the real host changes"],
]);

/** Components scanned, in the order they appear in the URI. */
const COMPONENTS = [
  ["userinfo", (ctx: InspectionContext) => ctx.userinfo],
  ["host", (ctx: InspectionContext) => ctx.rawHost],
  ["path", (ctx: InspectionContext) => ctx.path],
  ["query", (ctx: InspectionContext) => ctx.query],
  ["fragment", (ctx: InspectionContext) => ctx.fragment],
] as const;

/** Cap the detail string: the finding is "there is a sandwiched code point", not a census. */
const MAX_TOKENS = 3;

const isAsciiAlnum = (ch: string | undefined): boolean =>
  ch !== undefined && ch.length === 1 && /[A-Za-z0-9]/.test(ch);

/**
 * Scan one component for a non-ASCII code point whose low byte is dangerous and
 * which is isolated between two ASCII alphanumerics. Returns rendered tokens.
 */
function scan(name: string, value: string): string[] {
  // Fast path: pure ASCII components can never match.
  // eslint-disable-next-line no-control-regex
  if (!/[^\x00-\x7F]/.test(value)) return [];

  const cps = [...value];
  const found: string[] = [];
  for (let i = 1; i < cps.length - 1; i += 1) {
    const cp = cps[i]!.codePointAt(0)!;
    if (cp < 0x80) continue;
    const gloss = DANGEROUS_LOW_BYTE.get(cp & 0xff);
    if (gloss === undefined) continue;
    if (!isAsciiAlnum(cps[i - 1]) || !isAsciiAlnum(cps[i + 1])) continue;
    const hex = cp.toString(16).toUpperCase().padStart(4, "0");
    found.push(`U+${hex} in ${name} (low byte ${gloss})`);
  }
  return found;
}

/**
 * T2.3 — low-byte-truncation characters (`LINK-ibwuayzo`). Scoring, 0.6.
 *
 * A code point above U+007F whose **low byte is a dangerous ASCII byte**, sitting
 * **isolated between two ASCII alphanumerics**. When a lossy conversion narrows
 * UTF-16 code units to single bytes — `Buffer.from(s, 'latin1')`, a `charCodeAt`
 * masked to 8 bits, an ill-advised `wchar_t` downcast — U+560A becomes LF and
 * U+560D becomes CR. The dangerous byte does not exist in the input, so no
 * byte-scan can see it, which is why `control_char` cannot reach this class even
 * though it handles every direct form (raw, percent-encoded, double-encoded).
 * References: filedescriptor 2015; Node CVE-2018-12116.
 *
 * **The isolation guard is the whole design, and it is not a heuristic flourish —
 * it is what makes this a claim about the STRING rather than about a consumer's
 * bug.** Truncation-reachability alone is worthless as a firing condition: 2,357
 * assigned code points narrow to CR/LF, ~1,167 to `/`, ~1,167 to `@`, and 492 of
 * the whitespace set are everyday CJK — 上 下 不 有 而 名 同 看 國 程 載 選 尋 among
 * them. Flagging on reachability alone would flag 下載 ("download") and a large
 * share of real Chinese and Japanese URLs. The guard is measured rather than
 * asserted, and the measurement is executable rather than quoted:
 * the realistic-multilingual set is `REALISTIC_MULTILINGUAL_URLS` in
 * `packages/core/test/corpus/vectors.ts`, and
 * `packages/core/test/low-byte-truncation.test.ts` pins every member quiet and
 * reports the derived counts — which JP/CN/KR/RU/GR URLs are covered, which
 * corpus rows fire, and that the only rows this code carries on its own are the
 * two fixtures written for it. Sizes belong in that test output, not in a
 * sentence: three restated ones had gone stale by `LINK-dhtmcqva`.
 * CJK clusters with CJK or sits beside punctuation; a lone non-ASCII
 * code point wedged between two ASCII alphanumerics is the anomaly, and it is a
 * property of the string that every reader can check.
 *
 * Weight 0.6 is **parity with `control_char`**, which catches the direct form of
 * the identical attack. This variant is strictly harder to see, so parity is the
 * defensible floor; pricing it above 0.6 would assert it is worse than an actual
 * embedded newline. Revisiting the weight is tracked at `LINK-tyjxigyc`, which
 * records why "the further from ASCII, the more suspicious" must NOT be the
 * grounds for raising it — that is a proxy for "not English", not for deceptive,
 * and it is the reasoning that produced the rejected naive rule.
 */
export const lowByteTruncation: Detector = {
  id: "low_byte_truncation",
  layer: "lexical",
  run(ctx) {
    const hits: string[] = [];
    let total = 0;

    for (const [name, get] of COMPONENTS) {
      const value = get(ctx);
      if (value === null || value === "") continue;
      for (const token of scan(name, value)) {
        total += 1;
        if (hits.length < MAX_TOKENS) hits.push(token);
      }
    }

    if (total === 0) return [];
    const more = total > hits.length ? ` (+${total - hits.length} more)` : "";
    return [
      {
        code: "low_byte_truncation",
        detail:
          `non-ASCII code point wedged between ASCII alphanumerics whose low byte is a ` +
          `dangerous ASCII byte: ${hits.join(", ")}${more} — a lossy UTF-16-to-byte ` +
          `narrowing materializes that byte, and no byte-scan of the input can see it`,
      },
    ];
  },
};
