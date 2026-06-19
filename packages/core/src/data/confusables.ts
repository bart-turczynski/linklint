/**
 * Curated high-risk confusables subset (OQ-1 / NFR-DATA-2). Maps a confusable
 * character to the ASCII/Latin character it is visually confusable with. Focused
 * on the Cyrillic and Greek Latin-lookalikes that drive real homograph attacks,
 * rather than the full Unicode confusables.txt (bundle-size trade-off).
 *
 * Encoded as [confusableCodepoint, targetChar] so this source stays pure ASCII.
 * Version: dataVersions.unicodeConfusables = "curated-v1".
 */
const RAW: Array<[number, string]> = [
  // ── Cyrillic lowercase → Latin ──
  [0x0430, "a"], // а
  [0x0435, "e"], // е
  [0x043e, "o"], // о
  [0x0440, "p"], // р
  [0x0441, "c"], // с
  [0x0443, "y"], // у
  [0x0445, "x"], // х
  [0x0455, "s"], // ѕ
  [0x0456, "i"], // і
  [0x0458, "j"], // ј
  [0x04bb, "h"], // һ
  [0x051b, "q"], // ԛ
  [0x051d, "w"], // ԝ
  [0x043d, "h"], // н (visually h-ish in some fonts; conservative)
  // ── Cyrillic uppercase → Latin ──
  [0x0410, "A"], // А
  [0x0412, "B"], // В
  [0x0415, "E"], // Е
  [0x041a, "K"], // К
  [0x041c, "M"], // М
  [0x041d, "H"], // Н
  [0x041e, "O"], // О
  [0x0420, "P"], // Р
  [0x0421, "C"], // С
  [0x0422, "T"], // Т
  [0x0423, "Y"], // У
  [0x0425, "X"], // Х
  // ── Greek lowercase → Latin ──
  [0x03bf, "o"], // ο
  [0x03b1, "a"], // α
  [0x03c1, "p"], // ρ
  [0x03bd, "v"], // ν
  [0x03c4, "t"], // τ
  // ── Greek uppercase → Latin ──
  [0x039f, "O"], // Ο
  [0x0391, "A"], // Α
  [0x0392, "B"], // Β
  [0x0395, "E"], // Ε
  [0x0397, "H"], // Η
  [0x0399, "I"], // Ι
  [0x039a, "K"], // Κ
  [0x039c, "M"], // Μ
  [0x039d, "N"], // Ν
  [0x03a1, "P"], // Ρ
  [0x03a4, "T"], // Τ
  [0x03a7, "X"], // Χ
  [0x03a5, "Y"], // Υ
  [0x0396, "Z"], // Ζ
  // ── Other Latin-script lookalikes ──
  [0x0131, "i"], // ı dotless i
  [0x0251, "a"], // ɑ latin alpha
  [0x0261, "g"], // ɡ script g
];

export interface ConfusableTarget {
  /** The ASCII/Latin character this is confusable with. */
  target: string;
  /** A human-readable description, e.g. `"a (U+0061)"`. */
  confusableWith: string;
}

function cpHex(ch: string): string {
  return `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;
}

/** Lookup table: confusable character → its Latin target. */
export const CONFUSABLES: ReadonlyMap<string, ConfusableTarget> = new Map(
  RAW.map(([cp, target]) => {
    const ch = String.fromCodePoint(cp);
    return [ch, { target, confusableWith: `${target} (${cpHex(target)})` }];
  }),
);
