/**
 * PhishTank online-valid CSV feed parser (LINK-lddpffio, M5a).
 *
 * Reduces a PhishTank `online-valid.csv` export to normalized
 * {@link PhishTankRecord}s. Column order:
 *
 *   phish_id, url, phish_detail_url, submission_time, verified,
 *   verification_time, online, target
 *
 * The first non-empty line is the column header (unlike URLhaus, PhishTank uses
 * no `#` comment block). A genuinely empty feed (header only, 0 records) is valid.
 * Input that is not a PhishTank CSV — an HTML error page, a JSON body, a
 * truncated response — is `malformed` and returns `null`, so the updater reports
 * a failure and never overwrites a good snapshot.
 */

import { parseCsvRow, splitCsvLines } from "./csv.js";
import type { PhishTankRecord } from "./phishtank-types.js";

/** Expected data column count of a PhishTank online-valid CSV row. */
const PHISHTANK_COLUMN_COUNT = 8;

/**
 * Parse a PhishTank online-valid CSV feed. Returns the normalized records, or
 * `null` when the body is not recognizably a PhishTank CSV export.
 */
export function parsePhishTankCsv(body: string): { readonly records: PhishTankRecord[] } | null {
  if (typeof body !== "string" || body.trim() === "") return null;

  let recognized = false;
  const records: PhishTankRecord[] = [];

  for (const line of splitCsvLines(body)) {
    const fields = parseCsvRow(line);
    if (fields === null || fields.length < PHISHTANK_COLUMN_COUNT) continue;

    // The header row signs the file as a genuine PhishTank export and is skipped.
    if (isHeaderRow(fields)) {
      recognized = true;
      continue;
    }

    const record = toRecord(fields);
    if (record !== null) {
      recognized = true;
      records.push(record);
    }
  }

  if (!recognized) return null;
  return { records };
}

function isHeaderRow(fields: readonly string[]): boolean {
  return fields[0]?.trim().toLowerCase() === "phish_id" && fields[1]?.trim().toLowerCase() === "url";
}

function toRecord(fields: readonly string[]): PhishTankRecord | null {
  const phishId = fields[0]?.trim() ?? "";
  const url = fields[1]?.trim() ?? "";
  if (phishId === "" || url === "") return null;

  return {
    phishId,
    url,
    detailUrl: nonEmpty(fields[2]),
    submissionTime: isoInstant(fields[3]),
    verified: isYes(fields[4]),
    verificationTime: isoInstant(fields[5]),
    online: isYes(fields[6]),
    target: nonEmpty(fields[7]),
  };
}

function isYes(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "yes";
}

function nonEmpty(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed !== undefined && trimmed !== "" ? trimmed : null;
}

/** Validate a PhishTank timestamp and re-emit it as a canonical ISO-8601 instant, else `null`. */
function isoInstant(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (trimmed === undefined || trimmed === "") return null;
  const ms = Date.parse(trimmed);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}
