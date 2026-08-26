import type { Detector, DetectorFinding, InspectionContext } from "./types.js";

/**
 * `best_fit_mapping` (scoring, weight 0.50 -> medium). A code point in the path
 * or query that a Windows ANSI **best-fit** conversion replaces with an ASCII
 * delimiter, sitting where that delimiter would be read as one.
 *
 * ── The claim is about a conversion, not about a character looking odd ──────
 * `WideCharToMultiByte` called for an ANSI codepage without
 * `WC_NO_BEST_FIT_CHARS` does not fail on a code point the codepage cannot
 * represent. It substitutes a "best fit" ASCII character from a table Microsoft
 * publishes per codepage. U+00A5 YEN SIGN becomes `\` under codepage 932,
 * because JIS X 0201 puts the yen sign at 0x5C; U+20A9 WON SIGN becomes `\`
 * under codepage 949, because KS X 1003 does the same; the Halfwidth and
 * Fullwidth Forms collapse onto their ASCII counterparts under the single-byte
 * codepages. So a string a URL parser reads as one path segment becomes, inside
 * the consuming process, a segment plus a separator plus another segment — or a
 * closed quote, or an extra query parameter. Orange Tsai, "WorstFit", Black Hat
 * EU 2024; CVE-2024-4577 (PHP-CGI argument injection on Windows) is the
 * disclosed consequence class.
 *
 *   https://example.com/path¥win     -> was 0.00, zero reasons
 *   https://example.com/?p=¥share    -> was 0.00, zero reasons
 *
 * ── Reconciled with `separator_lookalike`, which ignores path/query ─────────
 * That code (0.50) scans the AUTHORITY only, and `separator-lookalike.ts` states
 * the exclusion in its own header: an ideographic full stop is ordinary CJK
 * punctuation inside a path segment (`/記事。html`), so path and query are out
 * of scope there on purpose. Nothing here disturbs that decision, on three
 * counts:
 *
 *  1. **Different question.** That code asks whether IDNA/NFKC normalization
 *     folds a character onto a URL delimiter, hiding the real HOST from a
 *     non-normalizing parser. This one asks whether a named platform API
 *     substitutes an ASCII character from a published table. The tables differ,
 *     and so do the consequences.
 *  2. **`。` is absent here for a mechanical reason.** U+3002 has an exact
 *     representation in codepages 932, 949 and 950, so no best-fit substitution
 *     happens to it and it is not a member of the table below. `/記事。html` is
 *     quiet under this code by construction, not by a guard.
 *  3. **The guard refuses the exact neighbourhood that decision protects.** A
 *     character with non-ASCII text on either side is prose, and is skipped —
 *     `/記事／html` stays quiet.
 *
 * ── `／` (U+FF0F), the hard case, and the verdict ───────────────────────────
 * It is in the table. It is also ordinary CJK punctuation, which is exactly why
 * flagging it bare would be an FP generator, and why the guard rather than the
 * character carries the weight: `/記事／html` is quiet, `/path／win` is not. The
 * distinction is not aesthetic. A fullwidth solidus wedged between ASCII letters
 * is a path segment boundary that the URL string declines to declare, and the
 * reader can check that property without knowing any Chinese.
 *
 * ── The guard, which is the whole design ───────────────────────────────────
 * Membership in the table is not a firing condition. A yen sign is a currency
 * sign, a fullwidth ampersand is CJK typesetting, and a URL that carries either
 * is not thereby deceptive. Two conditions place the materialized delimiter:
 *
 *  1. **An ASCII letter immediately on one side.** A currency sign in currency
 *     use abuts digits (`?price=¥1000`, `?price=1000¥`); a delimiter separates
 *     name-shaped tokens. This is the condition that keeps prices quiet.
 *  2. **No non-ASCII letter or digit immediately on either side.** A character
 *     embedded in non-ASCII text is being read as text. This is the condition
 *     that keeps CJK paths quiet.
 *
 * A neighbour that is itself in the table counts as neither — it materializes to
 * ASCII too, so a run like `＼＼server＼share` is judged on the member that has
 * real text beside it rather than being disqualified by its own neighbours.
 *
 * ── What is deliberately NOT in the table ──────────────────────────────────
 *  - **`.` and `-` as targets.** Both are unremarkable inside a path, so a
 *     materialized one crosses no boundary. `-` also carries the CVE-2024-4577
 *     vector (U+00AD SOFT HYPHEN), which reaches `invisible_char` at weight 1
 *     already.
 *  - **Curly quotes and apostrophes** (U+2018, U+2019, U+201C, U+201D). They
 *     best-fit to `'` and `"`, and they are ordinary orthography in running
 *     text; `?title=“hello”` is a title, and reading it as an attack is the
 *     mistake this file exists to avoid.
 *
 * ── Weight: 0.50, argued from the table ────────────────────────────────────
 * Parity with `separator_lookalike`, its closest peer in kind — a character that
 * puts a structural boundary where the string declares none. Below
 * `low_byte_truncation` and `control_char` (0.60), which materialize CR, LF, NUL
 * or `@`: a second line on the wire or a moved authority is a worse outcome than
 * a re-read file path or a broken quote, and those codes need no platform
 * assumption. Above `encoding_obfuscation` (0.35), which names an encoding step
 * without naming a mechanism; this names the API, the codepage and the
 * substitution. It lands `medium` — reviewable, and it does not trip the default
 * `--fail-on high` gate alone, which is right while reachability depends on the
 * consumer running Windows and converting without `WC_NO_BEST_FIT_CHARS`.
 *
 * ── Scope ──────────────────────────────────────────────────────────────────
 * Path and query. A yen or won sign in the host is fail-closed `invalid`
 * already, a fullwidth solidus in the authority is `separator_lookalike`, and a
 * fragment is not sent to a server, so widening past path and query would add
 * surface without adding a reachable consumer.
 *
 * Pure, synchronous, no network/fs.
 */

/** The ASCII character a best-fit conversion substitutes, and the grammar it delimits. */
interface BestFit {
  /** The ASCII character the substitution yields. */
  to: string;
  /** Where the substituted character is a delimiter. */
  gloss: string;
}

const WINDOWS_PATH = "a Windows path separator";
const SHELL_QUOTE = "a command-line quote delimiter";
const SHELL_OP = "a command-line operator";
const URL_DELIM = "a URL delimiter";

/**
 * Windows ANSI best-fit substitutions whose target is a delimiter in a grammar
 * the URL string does not itself declare. Sourced from Microsoft's published
 * per-codepage best-fit tables; the codepage that matters is named for the two
 * currency signs, whose substitution is a JIS/KS round-trip rather than a
 * shape match.
 */
const BEST_FIT = new Map<number, BestFit>([
  [0x00a5, { to: "\\", gloss: `${WINDOWS_PATH} (codepage 932 — JIS X 0201 puts ¥ at 0x5C)` }],
  [0x20a9, { to: "\\", gloss: `${WINDOWS_PATH} (codepage 949 — KS X 1003 puts ₩ at 0x5C)` }],
  [0xffe5, { to: "\\", gloss: WINDOWS_PATH }],
  [0xffe6, { to: "\\", gloss: WINDOWS_PATH }],
  [0xff3c, { to: "\\", gloss: WINDOWS_PATH }],
  [0xfe68, { to: "\\", gloss: WINDOWS_PATH }],
  [0xff0f, { to: "/", gloss: URL_DELIM }],
  [0xff02, { to: '"', gloss: SHELL_QUOTE }],
  [0xff07, { to: "'", gloss: SHELL_QUOTE }],
  [0xff06, { to: "&", gloss: `${URL_DELIM} and ${SHELL_OP}` }],
  [0xff1d, { to: "=", gloss: URL_DELIM }],
  [0xff5c, { to: "|", gloss: SHELL_OP }],
  [0xff1c, { to: "<", gloss: SHELL_OP }],
  [0xff1e, { to: ">", gloss: SHELL_OP }],
]);

/**
 * The source code points, exposed so a test can assert MEMBERSHIP separately
 * from PLACEMENT. The two questions are distinct and the second one is the
 * design: `packages/core/test/best-fit-mapping.test.ts` reads this to show that
 * U+FF0F is in the table and still quiet inside CJK prose, and that U+3002 is
 * absent from it entirely.
 */
export const BEST_FIT_SOURCES: ReadonlySet<number> = new Set(BEST_FIT.keys());

/** Components scanned, in the order they appear in the URI. */
const COMPONENTS = [
  ["path", (ctx: InspectionContext) => ctx.path],
  ["query", (ctx: InspectionContext) => ctx.query],
] as const;

/** Cap the detail: the finding is "a delimiter would materialize here", not a census. */
const MAX_TOKENS = 3;

/** Guard condition 1 — a name-shaped token on one side of the substitution. */
const isAsciiLetter = (ch: string | undefined): boolean =>
  ch !== undefined && ch.length === 1 && /[A-Za-z]/.test(ch);

/**
 * Guard condition 2 — non-ASCII text on either side means the character is being
 * read as text. A neighbour that is itself a best-fit source is transparent: it
 * materializes to ASCII as well, so it is no evidence of prose.
 */
const isForeign = (ch: string | undefined): boolean => {
  if (ch === undefined) return false;
  const cp = ch.codePointAt(0)!;
  return cp > 0x7f && !BEST_FIT.has(cp);
};

const cp = (n: number): string => `U+${n.toString(16).toUpperCase().padStart(4, "0")}`;

/** Scan one component, returning a rendered token for each placed substitution. */
function scan(name: string, value: string): string[] {
  // Fast path: a pure-ASCII component holds no best-fit source.
  // eslint-disable-next-line no-control-regex
  if (!/[^\x00-\x7F]/.test(value)) return [];

  const chars = [...value];
  const found: string[] = [];
  for (let i = 0; i < chars.length; i += 1) {
    const code = chars[i]!.codePointAt(0)!;
    const hit = BEST_FIT.get(code);
    if (hit === undefined) continue;
    const before = chars[i - 1];
    const after = chars[i + 1];
    if (isForeign(before) || isForeign(after)) continue;
    if (!isAsciiLetter(before) && !isAsciiLetter(after)) continue;
    found.push(`'${chars[i]!}' (${cp(code)} → '${hit.to}', ${hit.gloss}) in ${name}`);
  }
  return found;
}

export const bestFitMapping: Detector = {
  id: "best_fit_mapping",
  layer: "lexical",
  run(ctx: InspectionContext): DetectorFinding[] {
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
        code: "best_fit_mapping",
        detail:
          `path/query carries a code point that a Windows ANSI best-fit conversion ` +
          `replaces with an ASCII delimiter, placed between name-shaped tokens: ` +
          `${hits.join(", ")}${more} — a consumer converting without ` +
          `WC_NO_BEST_FIT_CHARS reads a boundary the URL does not declare`,
      },
    ];
  },
};
