/**
 * URLhaus CSV dump parser (LINK-qzybihpz, M4a).
 *
 * Reduces a URLhaus Community API CSV export to normalized {@link UrlhausRecord}s.
 * The export is an RFC 4180-style CSV whose every field is double-quoted, led by a
 * block of `#` comment/metadata lines and a `#`-prefixed column header. Column
 * order (URLhaus online/full dumps):
 *
 *   id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
 *
 * A genuinely empty dump (0 records) is valid and yields `{ records: [] }`. Input
 * that is not a URLhaus CSV at all — an HTML error page, a JSON error body, a
 * truncated response — is `malformed` and returns `null`, so the updater reports a
 * failure and never overwrites a good snapshot with garbage.
 */

import { parseCsvRow, splitCsvLines } from "./csv.js";
import type { UrlhausRecord, UrlhausUrlStatus } from "./types.js";

/** Expected data column count of a URLhaus CSV row. */
const URLHAUS_COLUMN_COUNT = 9;

/**
 * Parse a URLhaus CSV dump. Returns the normalized records, or `null` when the
 * body is not recognizably a URLhaus CSV export.
 */
export function parseUrlhausCsv(body: string): { readonly records: UrlhausRecord[] } | null {
  if (typeof body !== "string" || body.trim() === "") return null;

  let recognized = false;
  const records: UrlhausRecord[] = [];

  for (const line of splitCsvLines(body)) {
    if (line.startsWith("#")) {
      // The abuse.ch header block signs the file as a genuine URLhaus export.
      if (/urlhaus/i.test(line)) recognized = true;
      continue;
    }

    const fields = parseCsvRow(line);
    if (fields === null || fields.length < URLHAUS_COLUMN_COUNT) continue;
    const record = toRecord(fields);
    if (record !== null) {
      recognized = true;
      records.push(record);
    }
  }

  // Neither the abuse.ch header nor a single parseable data row: not a URLhaus CSV.
  if (!recognized) return null;
  return { records };
}

function toRecord(fields: readonly string[]): UrlhausRecord | null {
  const id = fields[0]?.trim() ?? "";
  const url = fields[2]?.trim() ?? "";
  // A record without an id or a URL is unusable; skip it rather than fabricate one.
  if (id === "" || url === "") return null;

  const tags = (fields[6] ?? "")
    .split(",")
    .map((tag) => tag.trim())
    .filter((tag) => tag !== "");

  return {
    id,
    url,
    dateAdded: isoInstant(fields[1]),
    status: urlStatus(fields[3]),
    lastOnline: isoInstant(fields[4]),
    threat: nonEmpty(fields[5]),
    tags,
    reporter: nonEmpty(fields[8]),
  };
}

function urlStatus(value: string | undefined): UrlhausUrlStatus {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "online") return "online";
  if (normalized === "offline") return "offline";
  return "unknown";
}

function nonEmpty(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed !== undefined && trimmed !== "" ? trimmed : null;
}

/**
 * Validate a URLhaus date (`YYYY-MM-DD HH:MM:SS` UTC) and re-emit it as a
 * canonical ISO-8601 instant, else `null`.
 */
function isoInstant(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (trimmed === undefined || trimmed === "") return null;
  // URLhaus timestamps are space-separated UTC; normalize to an ISO instant.
  const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)
    ? `${trimmed.replace(" ", "T")}Z`
    : trimmed;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}
