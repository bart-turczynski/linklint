/**
 * Shared CSV mechanics for caller-owned feed parsers (Epic M mirrors).
 *
 * URLhaus and PhishTank both publish RFC 4180-style CSV exports whose fields are
 * double-quoted with `""` escaping a literal quote. This module owns only the
 * mechanical line/field splitting; each feed's column mapping and validation stay
 * in that feed's own parser.
 */

/** Split CSV text into non-empty lines, tolerant of CRLF/CR/LF endings. */
export function splitCsvLines(body: string): string[] {
  return body.split(/\r\n|\r|\n/).filter((line) => line.trim() !== "");
}

/**
 * Split one RFC 4180-style CSV line into fields. Fields may be double-quoted, with
 * `""` escaping a literal quote. Returns `null` on an unterminated quote.
 */
export function parseCsvRow(line: string): string[] | null {
  const fields: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i]!;
    if (inQuotes) {
      if (char === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      fields.push(field);
      field = "";
    } else {
      field += char;
    }
  }

  if (inQuotes) return null;
  fields.push(field);
  return fields;
}
