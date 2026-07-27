/**
 * Line-oriented URL extraction shared by the `batch` subcommand and `check`'s
 * stdin path. Pure string processing — no I/O — so it is unit-testable.
 */

/**
 * Characters `String.prototype.trim` removes that we must NOT remove.
 *
 * `trim` strips ECMA-262 *LineTerminator*s as well as whitespace, and that set
 * includes U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR — the exact two
 * characters `invisible_char` scores as a blocker (`LINK-bitralnj`). Trimming
 * them here silently sanitized the input before it was ever inspected, so
 * `https://example.com/?a=<U+2028>` scored 1.00/critical when passed as an
 * argument and 0.00/info when read from a file. The CLI must not clean an input
 * into looking safer than it is.
 *
 * U+FEFF (BOM) is deliberately NOT in this set: `trim` removes it, and a BOM at
 * the head of a file is a file-encoding artifact rather than part of the URL.
 */
const PRESERVED_BY_TRIM = new RegExp("[\u2028\u2029]", "u");

/**
 * Trim ASCII/Unicode whitespace without removing characters that carry a
 * finding. Only leading and trailing runs are considered, so interior content is
 * untouched either way.
 */
function trimPreservingSignal(raw: string): string {
  let start = 0;
  let end = raw.length;
  while (start < end && raw[start]!.trim() === "" && !PRESERVED_BY_TRIM.test(raw[start]!)) start++;
  while (end > start && raw[end - 1]!.trim() === "" && !PRESERVED_BY_TRIM.test(raw[end - 1]!)) end--;
  return raw.slice(start, end);
}

/**
 * Parse a chunk of text into a list of URLs, one per line. Each line is
 * trimmed; blank lines and comment lines (first non-whitespace char `#`) are
 * skipped.
 *
 * Trimming preserves U+2028/U+2029 — see `PRESERVED_BY_TRIM`.
 */
export function parseUrlLines(text: string): string[] {
  const urls: string[] = [];
  for (const raw of text.split("\n")) {
    const line = trimPreservingSignal(raw);
    if (line === "") continue;
    if (line.startsWith("#")) continue;
    urls.push(line);
  }
  return urls;
}
