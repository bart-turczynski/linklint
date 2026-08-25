import type { Detector } from "./types.js";
import { boundedDecode } from "../parse/decode.js";

const HAS_PERCENT = /%[0-9a-fA-F]{2}/;
const ALL_PERCENT = /%[0-9a-fA-F]{2}/g;

/**
 * Overlong UTF-8 lead/continuation byte pairs, expressed as percent-encoded
 * octets. An overlong sequence encodes a code point in more bytes than the
 * minimal form requires; permissive decoders fold it back to the canonical
 * (often structural) ASCII char — e.g. `%C0%AF` → `/`. We ground detection in
 * the byte pattern, not any single payload:
 *  - C0/C1 lead: every 2-byte sequence starting C0/C1 is overlong (encodes a
 *    code point < U+0080, which is a 1-byte char).
 *  - E0 lead with continuation 80–9F: overlong 3-byte (fits in ≤ 2 bytes).
 *  - F0 lead with continuation 80–8F: overlong 4-byte (fits in ≤ 3 bytes).
 * Each continuation byte is 80–BF. The patterns are anchored, fixed-width, and
 * non-backtracking, so they stay within the worst-case `inspect() < 5ms`
 * budget.
 */
const OVERLONG_UTF8 =
  /%[cC][01]%[89aAbB][0-9a-fA-F]|%[eE]0%[89][0-9a-fA-F]%[89aAbB][0-9a-fA-F]|%[fF]0%8[0-9a-fA-F]%[89aAbB][0-9a-fA-F]%[89aAbB][0-9a-fA-F]/;

/**
 * An encoded WHATWG **double-dot path segment** (`LINK-dpahotkg`). The URL
 * Standard enumerates the double-dot segment by name and by exhaustive list —
 * `..`, `.%2e`, `%2e.`, `%2e%2e`, ASCII case-insensitive — and every conforming
 * parser pops the parent for all four. The bare `..` is honest: every reader
 * agrees it is a traversal and nothing is concealed. The three encoded
 * spellings resolve as a traversal while reading as literal text, which is
 * architecture §1.1 form 1 (`normalize(input) !== input`); against a reader that
 * string-matches only the unencoded spelling it is also form 2. The spellings
 * come from the standard, so no server behavior is assumed.
 *
 * **Matched per segment, anchored — this is the whole design.** A segment that
 * is exactly one of these IS `..` to every conforming reader, so it can never be
 * a filename. A substring match reaches ordinary filenames that no parser pops:
 * `/files/report%2e.pdf`, `/dl/My%20File%2e.txt`, `/pkg/lodash%2e.min.js`,
 * `/x/.%2ehidden/file`, `/docs/file%2e%2etxt`. It also mis-reads
 * `/a/.%2e%2e/admin`, which is not on the standard's list and which Node leaves
 * un-popped. Measured over 13 encoded-dot benign paths, the substring form
 * produced 4 false positives and the segment-bounded form produced 0, with both
 * catching 3 of 3 attack spellings.
 *
 * A `%2e%2e` embedded in a longer segment used to fire here. It no longer does:
 * it becomes a traversal only if something decodes the escape and then re-splits
 * the path, which is application code below the URL layer and out of scope per
 * §1.1. Where such a path also carries an encoded separator
 * (`/%2e%2e%2fadmin`), the encoded-separator signal still fires and is the
 * honest one — its lean on servers that decode `%2F` is the documented,
 * in-scope lean, and it is not this signal's claim to make.
 *
 * Single-dot segments (`.`, `%2e`) are deliberately absent: they resolve to the
 * same directory, so nothing about the destination changes.
 */
const ENCODED_DOUBLE_DOT_SEGMENT = /^(?:\.%2e|%2e\.|%2e%2e)$/i;

/**
 * FR-D-10 — percent-encoding obfuscation. Scoring. Deliberately narrow to avoid
 * flagging the legitimate encoding common in query strings (e.g. an encoded
 * `redirect_uri`). Flags only the high-signal cases:
 *  - any percent-encoding in the host (hosts are never legitimately encoded);
 *  - double-encoding (`%25…`) anywhere;
 *  - triple-or-deeper nesting (≥3 percent-decode passes to reach a stable form);
 *  - an overlong UTF-8 sequence whose canonical form is a one-byte char;
 *  - an encoded control character anywhere;
 *  - an encoded path separator in the path, or a path segment that is one of
 *    the WHATWG standard's encoded double-dot spellings.
 */
export const encodingObfuscation: Detector = {
  id: "encoding_obfuscation",
  layer: "lexical",
  run(ctx) {
    const signals: string[] = [];
    const all = [ctx.rawHost, ctx.userinfo ?? "", ctx.path, ctx.query ?? "", ctx.fragment ?? ""].join(
      " ",
    );

    if (HAS_PERCENT.test(ctx.rawHost)) signals.push("percent-encoding in host");

    if (/%25/i.test(all)) signals.push("double-encoded (%25)");

    // Triple-or-deeper nesting: bounded by maxDecodeDepth, so no unbounded
    // recursion. ≥3 changing passes (or hitting the depth cap) means the input
    // was percent-encoded three or more levels deep (e.g. `%25252e` → `.`).
    if (HAS_PERCENT.test(all)) {
      const { passes, truncated } = boundedDecode(all, ctx.runtime.maxDecodeDepth);
      if (passes >= 3 || truncated) signals.push("triple-encoded (≥3 levels)");
    }

    if (OVERLONG_UTF8.test(all)) signals.push("overlong UTF-8 sequence");

    for (const m of all.match(ALL_PERCENT) ?? []) {
      const code = parseInt(m.slice(1), 16);
      if (code < 0x20 || code === 0x7f) {
        signals.push("encoded control character");
        break;
      }
    }

    if (/%2f|%5c/i.test(ctx.path)) signals.push("encoded path separator");
    if (ctx.path.split("/").some((segment) => ENCODED_DOUBLE_DOT_SEGMENT.test(segment)))
      signals.push("encoded '..' traversal");

    if (signals.length === 0) return [];
    return [
      {
        code: "encoding_obfuscation",
        detail: `percent-encoding obfuscation: ${[...new Set(signals)].join(", ")}`,
      },
    ];
  },
};
