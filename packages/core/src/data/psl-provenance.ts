/**
 * Provenance + staleness for the Public Suffix List snapshot linklint reasons
 * against (LINK-rkhuihjx / P2). Adopts the pattern pslr shipped in
 * `R/metadata.R` (`psl_version()` static provenance + `psl_outdated()`
 * time-relative check, PSLR-cowbpwsy).
 *
 * linklint's whole "the real host is evil.com" claim rides on the PSL bundled
 * inside tldts (pinned in {@link import("./versions.js").DATA_VERSIONS}). A
 * silently stale bundled PSL degrades embedded-domain / brand-homoglyph /
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
 * What a {@link PslProvenance.pslListDate} actually dates — and therefore which
 * direction of claim it can support (LINK-elzuacby).
 *
 * Write `S` for the true snapshot time and `R` for the recorded date.
 *
 * - `"exact"` — `R = S`. The date is the embedded snapshot's own timestamp, so
 *   `now − R` is the TRUE age. It can prove staleness *and* freshness.
 * - `"release-proxy"` — `R` is the packaging release date, and the list was
 *   regenerated from upstream at or before that build, so `S ≤ R`. Then
 *   `now − R ≤ now − S`: the computed age is a **LOWER BOUND (minimum)** on the
 *   true age. It can prove the snapshot is *at least* that old; it can never
 *   prove it is younger. A proxy date therefore proves staleness only, and
 *   leaves freshness undetermined.
 *
 * Omitting the field is read as `"release-proxy"` — the conservative direction,
 * so an unlabelled record can never be mistaken for proof of freshness.
 */
export type PslDateKind = "exact" | "release-proxy";

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
   * ISO date (`YYYY-MM-DD`) dating the bundled PSL snapshot, or `null` when
   * unknown. Read it together with {@link PslProvenance.dateKind}, which says
   * whether it dates the snapshot itself or merely its packaging.
   *
   * tldts exposes no upstream PSL commit date and no snapshot timestamp of any
   * kind (re-probed against tldts@7.4.10: its public surface is `parse`,
   * `getHostname`, `getPublicSuffix`, `getDomain`, `getFullDomain`,
   * `getSubdomain`, `getDomainWithoutSuffix` — nothing carries provenance), so
   * we record the tldts npm-release date as a **proxy**.
   */
  pslListDate: string | null;
  /**
   * Whether `pslListDate` is the snapshot's own date or a packaging proxy.
   * Defaults to `"release-proxy"` when omitted. See {@link PslDateKind} — this
   * is what decides whether a computed age is the true age or only a minimum.
   */
  dateKind?: PslDateKind;
  /** ISO date (`YYYY-MM-DD`) this provenance record was captured / verified. */
  retrievedAt: string;
}

/**
 * Provenance for the currently-pinned bundled PSL snapshot (tldts@7.4.10).
 *
 * tldts@7.4.10 was published to npm on 2026-07-30. tldts regenerates its bundled
 * list from upstream at release-build time, so the true snapshot is that date or
 * OLDER — the date is a `"release-proxy"`, not the snapshot's own timestamp, and
 * the age derived from it is a minimum (see {@link PslDateKind}). Verified
 * 2026-08-13. Bump the version, date and retrieval stamp together with
 * `DATA_VERSIONS.publicSuffixList` on every tldts pin change; only switch
 * `dateKind` to `"exact"` if tldts ever starts publishing the snapshot's date.
 */
export const PSL_PROVENANCE: PslProvenance = {
  tldtsVersion: "7.4.10",
  pslListDate: "2026-07-30",
  dateKind: "release-proxy",
  retrievedAt: "2026-08-13",
};

/** Result of a {@link pslOutdated} check. `null` fields mean "undetermined". */
export interface PslStaleness {
  /**
   * - `true` — the snapshot is PROVABLY older than `maxAgeDays`. Sound from an
   *   exact date and from a proxy date alike: a minimum age past the window is
   *   still past the window.
   * - `false` — the snapshot is PROVABLY within the window. Reachable only from
   *   a `"exact"` {@link PslProvenance.dateKind}; a packaging proxy cannot
   *   produce it (LINK-elzuacby).
   * - `null` — undetermined. Either the date is unknown/unparseable, or it is a
   *   proxy whose lower-bound age has not yet crossed the window, which leaves
   *   the true age unbounded above. Staleness is never assumed (mirrors pslr's
   *   NA-not-FALSE discipline).
   */
  stale: boolean | null;
  /**
   * Age in whole days computed from the provenance date, or `null` when that
   * date is unknown. Under a `"release-proxy"` date this is a **MINIMUM** age,
   * not the age: the true snapshot can be arbitrarily older. Compare it against
   * a window only in the "exceeds ⇒ stale" direction unless the record's
   * {@link PslProvenance.dateKind} is `"exact"`.
   */
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
 * The verdict is DIRECTIONAL, because the evidence is (LINK-elzuacby). A
 * packaging-release date bounds the snapshot's age from BELOW, so exceeding the
 * window proves staleness while staying inside it proves nothing — that case
 * returns `stale: null`, not `stale: false`. Only an `"exact"` snapshot date
 * can return `stale: false`.
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
  // Past the window: sound either way — a minimum age past the window is past it.
  if (ageDays > maxAgeDays) return { stale: true, ageDays };
  // Inside the window: only an exact snapshot date proves the snapshot itself is
  // that young. A proxy date leaves the true age unbounded above -> undetermined.
  return { stale: provenance.dateKind === "exact" ? false : null, ageDays };
}

/** The PSL-snapshot metadata surfaced on every {@link import("../schema/result.js").InspectResult}. */
export interface PslSnapshot {
  /**
   * ISO date (`YYYY-MM-DD`) dating the bundled PSL snapshot, or `null` if
   * unknown. With the currently-pinned tldts this is a packaging-release proxy,
   * so the snapshot is that date **or older**; `PSL_PROVENANCE.dateKind` (from
   * `linklint/metadata`) says which kind of date it is.
   */
  date: string | null;
  /**
   * A ONE-DIRECTIONAL staleness verdict against the default 180-day window
   * (LINK-elzuacby):
   *
   * - `true` — the snapshot is provably older than 180 days.
   * - `null` — undetermined. This is the normal value for the pinned bundle:
   *   `date` is a release-date proxy that bounds the age from below only, so
   *   until the bound crosses the window nothing about freshness is proven.
   *   `null` also covers an unknown `date`.
   * - `false` — provably within the window. Only an exact snapshot date can
   *   produce it, so the current release-proxy provenance never does.
   *
   * ADVISORY, and the one time-relative field on the result: it reflects
   * wall-clock time at inspection (`date` and every other field are
   * deterministic). Do not read `!== true` as freshness; test `=== true` to act
   * on proven staleness and treat `null` as "unknown", which is what it is.
   *
   * READ THIS AS AGE, NOT AS VERIFICATION. Even a `false` would mean only "the
   * snapshot is under 180 days old" — not "confirmed current against
   * publicsuffix.org". linklint has no network path and never contacts the
   * upstream list, so a young snapshot can still be missing rules added last
   * week. pslr retired its boolean `psl_outdated()` in 1.1.1 for exactly this
   * conflation (PSLR-cowbpwsy); linklint keeps a tri-state whose only positive
   * claim is one the offline evidence actually supports.
   */
  stale: boolean | null;
}

/**
 * The PSL-snapshot metadata for a result: static provenance date plus the
 * default-window staleness verdict computed against the current time. Used by
 * the serializer so every result carries the provenance of its trust boundary.
 */
export function currentPslSnapshot(now: Date = new Date()): PslSnapshot {
  return {
    date: PSL_PROVENANCE.pslListDate,
    stale: pslOutdated(180, { now }).stale,
  };
}
