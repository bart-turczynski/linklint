import type { DetectorFinding } from "./types.js";
import { authorityRegion, type AuthorityRegion } from "../parse/authority-region.js";

/**
 * J2 — `separator_lookalike` (Epic J, FR parser-differential). SCORING.
 *
 * Flags characters in the authority that a downstream layer (browser, IDNA/NFKC
 * normalization) maps to a STRUCTURAL ASCII delimiter — a dot or a slash — so
 * the real host hides from a parser that does not normalize. Tsai shows browsers
 * splitting on delimiters linklint's parser does not.
 *
 * Detected look-alikes:
 *  - dot delimiters (→ '.'): U+3002 ideographic full stop `evil。com`,
 *    U+FF0E fullwidth full stop, U+FF61 halfwidth ideographic full stop,
 *    U+2024 one-dot leader.
 *  - slash delimiters (→ '/'): U+FF0F fullwidth solidus `github.com／x@evil.zip`,
 *    U+2215 division slash.
 *
 * Scoped to the AUTHORITY region only (up to the first ASCII `/ ? #`). Two
 * precision guards keep legitimate input clean (SC-2):
 *  1. Path/query are ignored — an ideographic full stop is ordinary CJK
 *     punctuation inside a path segment (`/記事。html`) and must not flag.
 *  2. The authority must contain an ASCII alphanumeric — a Latin brand glued by
 *     a look-alike dot (`evil。com`) is the lure; a pure-CJK host typed with an
 *     ideographic dot is normal domain entry, not impersonation.
 */

interface Lookalike {
  char: string;
  /** The ASCII delimiter this character impersonates. */
  maps: "." | "/";
}

const LOOKALIKES = new Map<number, Lookalike>([
  [0x3002, { char: "。", maps: "." }], // IDEOGRAPHIC FULL STOP
  [0xff0e, { char: "．", maps: "." }], // FULLWIDTH FULL STOP
  [0xff61, { char: "｡", maps: "." }], // HALFWIDTH IDEOGRAPHIC FULL STOP
  [0x2024, { char: "․", maps: "." }], // ONE DOT LEADER
  [0xff0f, { char: "／", maps: "/" }], // FULLWIDTH SOLIDUS
  [0x2215, { char: "∕", maps: "/" }], // DIVISION SLASH
]);

const cp = (n: number): string => `U+${n.toString(16).toUpperCase().padStart(4, "0")}`;

/**
 * Scan the prepared input's authority for delimiter look-alikes. Returns a
 * single `separator_lookalike` finding listing every offending character, or `[]`.
 */
export function scanSeparatorLookalike(
  prepared: string,
  region: AuthorityRegion = authorityRegion(prepared),
): DetectorFinding[] {
  if (prepared === "") return [];

  const { authority, opaque } = region;
  if (opaque || authority === "") return [];

  // Guard 2: only domain-shaped authorities (some ASCII alnum) — not CJK prose.
  if (!/[A-Za-z0-9]/.test(authority)) return [];

  const found = new Map<number, Lookalike>();
  for (const ch of authority) {
    const code = ch.codePointAt(0)!;
    const hit = LOOKALIKES.get(code);
    if (hit) found.set(code, hit);
  }
  if (found.size === 0) return [];

  const parts = [...found].map(([code, h]) => `'${h.char}' (${cp(code)} → '${h.maps}')`);
  return [
    {
      code: "separator_lookalike",
      detail:
        "authority uses delimiter look-alikes that normalize to ASCII separators, " +
        `hiding the real host from a non-normalizing parser: ${parts.join(", ")}`,
    },
  ];
}
