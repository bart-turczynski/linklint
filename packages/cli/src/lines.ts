/**
 * Line-oriented URL extraction shared by the `batch` subcommand and `check`'s
 * stdin path. Pure string processing — no I/O — so it is unit-testable.
 */

/**
 * Parse a chunk of text into a list of URLs, one per line. Each line is
 * trimmed; blank lines and comment lines (first non-whitespace char `#`) are
 * skipped.
 */
export function parseUrlLines(text: string): string[] {
  const urls: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    if (line.startsWith("#")) continue;
    urls.push(line);
  }
  return urls;
}
