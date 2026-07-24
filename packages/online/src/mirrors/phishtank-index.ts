/**
 * PhishTank exact-URL lookup index (LINK-unqxyfce, M5b).
 *
 * PhishTank lists *exact* phishing URLs, so a match must be exact — a different
 * path or query is a different URL, and the host is never broadened. Both the
 * indexed records and the query URL pass through the shared {@link
 * canonicalizeUrl}. The index is built once from a caller-owned snapshot and
 * queried locally; the enricher performs no network I/O at check time.
 */

import { canonicalizeUrl } from "./url-canonical.js";
import type { PhishTankIndex, PhishTankRecord, PhishTankSnapshot } from "./phishtank-types.js";

/**
 * Build an exact-URL lookup index over a PhishTank snapshot. Records whose URL
 * cannot be canonicalized are dropped (they can never match exactly). When two
 * records canonicalize to the same URL, the first one wins.
 */
export function createPhishTankIndex(snapshot: PhishTankSnapshot): PhishTankIndex {
  const byUrl = new Map<string, PhishTankRecord>();
  for (const record of snapshot.records) {
    const key = canonicalizeUrl(record.url);
    if (key !== null && !byUrl.has(key)) byUrl.set(key, record);
  }

  return {
    metadata: snapshot.metadata,
    lookup(url: string): PhishTankRecord | null {
      const key = canonicalizeUrl(url);
      if (key === null) return null;
      return byUrl.get(key) ?? null;
    },
  };
}
