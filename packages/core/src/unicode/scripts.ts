/**
 * Script detection via ECMAScript Unicode property escapes (no bundled tables —
 * see dataVersions.unicodeScripts). Used by the mixed_script detector (FR-D-3),
 * the cross-script de-noiser that distinguishes a homograph attack from a
 * legitimate single-script IDN (Principle 5, SC-2).
 */

/** Scripts linklint classifies. Order matters only for first-match lookup. */
const SCRIPT_TESTS: Array<[string, RegExp]> = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Han", /\p{Script=Han}/u],
  ["Hiragana", /\p{Script=Hiragana}/u],
  ["Katakana", /\p{Script=Katakana}/u],
  ["Hangul", /\p{Script=Hangul}/u],
  ["Bopomofo", /\p{Script=Bopomofo}/u],
  ["Thai", /\p{Script=Thai}/u],
  ["Devanagari", /\p{Script=Devanagari}/u],
  ["Georgian", /\p{Script=Georgian}/u],
];

/**
 * Characters that don't belong to any single script: digits, punctuation,
 * hyphen, combining marks. They never count toward script-mixing.
 */
const SCRIPT_NEUTRAL = /[\p{Script=Common}\p{Script=Inherited}]/u;

/** The script of a single character, or `null` if neutral/unclassified. */
export function scriptOf(ch: string): string | null {
  if (SCRIPT_NEUTRAL.test(ch)) return null;
  for (const [name, re] of SCRIPT_TESTS) {
    if (re.test(ch)) return name;
  }
  return null;
}

/**
 * Script combinations that legitimately co-occur within one label and must NOT
 * be flagged as mixed (de-noising). Japanese mixes Han/Hiragana/Katakana;
 * Korean mixes Hangul/Han; Chinese mixes Han/Bopomofo.
 */
const COMPATIBLE_GROUPS: ReadonlyArray<ReadonlySet<string>> = [
  new Set(["Han", "Hiragana", "Katakana"]),
  new Set(["Han", "Hangul"]),
  new Set(["Han", "Bopomofo"]),
];

function isCompatible(scripts: Set<string>): boolean {
  if (scripts.size <= 1) return true;
  return COMPATIBLE_GROUPS.some((group) => [...scripts].every((s) => group.has(s)));
}

export interface MixedScriptResult {
  mixed: boolean;
  scripts: string[];
}

/** Distinct scripts present in a label, and whether it mixes incompatible ones. */
export function analyzeLabelScripts(label: string): MixedScriptResult {
  const scripts = new Set<string>();
  for (const ch of label) {
    const s = scriptOf(ch);
    if (s) scripts.add(s);
  }
  return { mixed: !isCompatible(scripts), scripts: [...scripts] };
}
