/**
 * Provenance + staleness for the Public Suffix List snapshot linklint reasons
 * against (LINK-rkhuihjx / P2). Adopts the pattern pslr shipped in
 * `R/metadata.R` (`psl_version()` static provenance + `psl_outdated()`
 * time-relative check, PSLR-cowbpwsy).
 *
 * linklint's whole "the real host is evil.com" claim rides on the PSL bundled
 * inside tldts (pinned in {@link import("./versions.js").DATA_VERSIONS}). A
 * silently stale bundled PSL degrades embedded-domain / brand-lookalike /
 * ambiguous-authority reasoning with NO signal to callers. This module exposes
 * the snapshot's provenance so consumers learn the provenance of the trust
 * boundary they are handed, and a pure offline staleness check so they can
 * decide whether to trust it.
 *
 * We do NOT fetch anything: the PSL ships inside tldts. The provenance below is
 * a hand-captured record verified at dependency-pin time (mirrors pslr's
 * data-raw provenance record); bump it deliberately whenever the pinned tldts
 * release changes, alongside `DATA_VERSIONS.publicSuffixList`.
 */

/**
 * Hand-captured provenance for the bundled PSL snapshot, recorded at
 * dependency-pin time. `pslListDate` is the best defensible date for the
 * snapshot; `null` when it cannot be determined (staleness then degrades to
 * "unknown" rather than being assumed either way).
 */
export interface PslProvenance {
  /**
   * The pinned tldts release that bundles the PSL snapshot. MUST equal the
   * `<version>` in `DATA_VERSIONS.publicSuffixList` ("tldts@<version>"); a test
   * pins the two together so a stamp can never silently drift.
   */
  tldtsVersion: string;
  /**
   * ISO date (`YYYY-MM-DD`) of the bundled PSL snapshot, or `null` when unknown.
   *
   * tldts does not expose the exact upstream PSL commit date, so we record the
   * tldts npm-release date as the snapshot proxy: tldts regenerates its bundled
   * list from the upstream PSL at release-build time, making the release date a
   * tight UPPER BOUND on the snapshot's age (the true list is at most a day or
   * two older). Staleness computed from it is therefore conservative — it can
   * only under-report age, never over-report it.
   */
  pslListDate: string | null;
  /** ISO date (`YYYY-MM-DD`) this provenance record was captured / verified. */
  retrievedAt: string;
}

/**
 * Provenance for the currently-pinned bundled PSL snapshot (tldts@7.4.3).
 *
 * tldts@7.4.3 was published to npm on 2026-06-15; that release date is the
 * snapshot proxy (see {@link PslProvenance.pslListDate}). Verified 2026-07-17.
 * Bump all three fields together with `DATA_VERSIONS.publicSuffixList` on every
 * tldts pin change.
 */
export const PSL_PROVENANCE: PslProvenance = {
  tldtsVersion: "7.4.3",
  pslListDate: "2026-06-15",
  retrievedAt: "2026-07-17",
};

/** Result of a {@link pslOutdated} check. `null` fields mean "undetermined". */
export interface PslStaleness {
  /**
   * `true` when the snapshot is older than `maxAgeDays`, `false` when fresher,
   * and `null` when the snapshot date is unknown/unparseable — staleness is
   * undetermined, never assumed (mirrors pslr's NA-not-FALSE discipline).
   */
  stale: boolean | null;
  /** Age of the snapshot in whole days, or `null` when the date is unknown. */
  ageDays: number | null;
}

const MS_PER_DAY = 86_400_000;

/**
 * Parse a `YYYY-MM-DD` (or full ISO 8601) snapshot date to epoch millis at UTC
 * midnight. Returns `null` for a missing/unparseable value so the caller
 * degrades to "unknown" rather than treating garbage as a real date.
 */
function parseSnapshotDate(value: string | null): number | null {
  if (value == null) return null;
  // Anchor a bare calendar date at UTC midnight; accept a full ISO timestamp too.
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Is the bundled PSL snapshot older than `maxAgeDays`? PURE and offline: reads
 * only the provenance record, never the network. Mirrors pslr's `psl_outdated()`.
 *
 * The Public Suffix List changes continually upstream, so a long-lived bundled
 * snapshot drifts from the live list; this is the signal to consider bumping the
 * tldts pin. When the snapshot date is unknown, both fields are `null`
 * (undetermined) rather than assumed fresh or stale.
 *
 * @param maxAgeDays Freshness window in days; must be a positive finite number.
 *   Defaults to 180.
 * @param opts.now Clock override (for testing); defaults to the current time.
 * @param opts.provenance Provenance override; defaults to {@link PSL_PROVENANCE}.
 */
export function pslOutdated(
  maxAgeDays = 180,
  opts: { now?: Date; provenance?: PslProvenance } = {},
): PslStaleness {
  if (!Number.isFinite(maxAgeDays) || maxAgeDays <= 0) {
    throw new RangeError("maxAgeDays must be a positive finite number of days");
  }
  const { now = new Date(), provenance = PSL_PROVENANCE } = opts;
  const snapshotMs = parseSnapshotDate(provenance.pslListDate);
  if (snapshotMs === null) return { stale: null, ageDays: null };

  const ageDays = Math.floor((now.getTime() - snapshotMs) / MS_PER_DAY);
  return { stale: ageDays > maxAgeDays, ageDays };
}

/** The PSL-snapshot metadata surfaced on every {@link import("../schema/result.js").InspectResult}. */
export interface PslSnapshot {
  /** ISO date (`YYYY-MM-DD`) of the bundled PSL snapshot, or `null` if unknown. */
  date: string | null;
  /**
   * `true` when the snapshot is older than the default 180-day freshness window,
   * `false` when fresher, `null` when the date is unknown. ADVISORY and the one
   * time-relative field on the result: it reflects wall-clock time at inspection
   * (`date` and every other field are deterministic). It flips only when the
   * snapshot actually crosses the window — which is exactly when callers should
   * be told the trust boundary they were handed has gone stale.
   */
  stale: boolean | null;
}

/**
 * The PSL-snapshot metadata for a result: static provenance date plus the
 * default-window staleness flag computed against the current time. Used by the
 * serializer so every result carries the provenance of its trust boundary.
 */
export function currentPslSnapshot(now: Date = new Date()): PslSnapshot {
  return {
    date: PSL_PROVENANCE.pslListDate,
    stale: pslOutdated(180, { now }).stale,
  };
}
