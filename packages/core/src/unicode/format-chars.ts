/**
 * Shared invisible / bidi character helpers. Used both by the parser (to derive
 * a visual "clean" host for validation) and by the invisible_char / bidi_override
 * detectors, so the definition of "invisible" lives in exactly one place.
 *
 * Regexes are built from \u escapes (rather than literal invisible characters)
 * so this source file stays pure ASCII and reviewable.
 */

/**
 * Bidirectional control characters (FR-D-5): the explicit overrides/embeddings
 * (U+202A-U+202E), isolates (U+2066-U+2069), the Arabic letter mark (U+061C),
 * and the LRM/RLM marks (U+200E/U+200F). These can visually reorder a URL.
 */
const BIDI_CONTROL = new RegExp("[\\u202A-\\u202E\\u2066-\\u2069\\u061C\\u200E\\u200F]", "u");

export function isBidiControl(ch: string): boolean {
  return BIDI_CONTROL.test(ch);
}

/**
 * Any invisible / zero-width / control / format character (Unicode Cc or Cf).
 * Covers tabs, newlines, zero-width spaces, BOM, soft hyphen, word joiner, etc.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}]/u;

export function isInvisible(ch: string): boolean {
  return INVISIBLE.test(ch);
}

/**
 * Invisible characters that are NOT bidi controls — what the invisible_char
 * detector owns (bidi controls are reported separately by bidi_override).
 */
export function isInvisibleNonBidi(ch: string): boolean {
  return isInvisible(ch) && !isBidiControl(ch);
}

/** Strip all invisible/format/control characters — yields the visual string. */
export function stripInvisible(input: string): string {
  let out = "";
  for (const ch of input) {
    if (!isInvisible(ch)) out += ch;
  }
  return out;
}

/** Format a codepoint as `U+XXXX`. */
export function codepointOf(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}
