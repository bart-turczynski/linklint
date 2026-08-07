import { describe, expect, it } from "vitest";
import {
  PSL_PROVENANCE,
  currentPslSnapshot,
  pslOutdated,
  type PslProvenance,
} from "../src/data/psl-provenance.js";
import { DATA_VERSIONS } from "../src/data/versions.js";

/**
 * P2 (LINK-rkhuihjx): PSL snapshot provenance + a PURE, offline staleness check.
 * Mirrors pslr's `psl_outdated()` NA-not-FALSE discipline: unknown date ->
 * undetermined (null), never assumed fresh or stale.
 *
 * LINK-elzuacby: the verdict is DIRECTIONAL. A packaging-release date R bounds
 * the true snapshot time S from above (S <= R), so `now - R` is a LOWER bound on
 * the true age — it can prove "at least this old", never "no older than this".
 * A proxy date therefore yields `true` or `null` and never `false`; only an
 * `"exact"` date can prove freshness. Every case below is clock-injected, so no
 * assertion moves with the wall clock or with a future tldts bump.
 */

// A fixed snapshot date so the stale/undetermined boundary is exact and
// deterministic. Default kind: the release proxy the real record uses.
const fixture: PslProvenance = {
  tldtsVersion: "0.0.0",
  pslListDate: "2026-01-01",
  dateKind: "release-proxy",
  retrievedAt: "2026-01-01",
};

// Same date, but dating the snapshot itself — the only kind that can prove
// freshness. tldts publishes no such date today; this is the shape the record
// would take if it ever did.
const exactFixture: PslProvenance = { ...fixture, dateKind: "exact" };

describe("PSL_PROVENANCE record", () => {
  it("stays in sync with the pinned tldts release in DATA_VERSIONS", () => {
    // publicSuffixList is "tldts@<version>"; the provenance version must match so
    // a stamp can never silently drift from the bundled list it describes.
    expect(DATA_VERSIONS.publicSuffixList).toBe(`tldts@${PSL_PROVENANCE.tldtsVersion}`);
  });

  it("records an ISO calendar date for the snapshot and retrieval", () => {
    const iso = /^\d{4}-\d{2}-\d{2}$/;
    expect(PSL_PROVENANCE.pslListDate).toMatch(iso);
    expect(PSL_PROVENANCE.retrievedAt).toMatch(iso);
  });

  // LINK-elzuacby. tldts@7.4.3 exports parse/getHostname/getPublicSuffix/
  // getDomain/getFullDomain/getSubdomain/getDomainWithoutSuffix and nothing
  // that dates the bundled list, so the npm release date is all we have. That
  // is a PROXY, and the record must say so — the whole one-directional verdict
  // below hangs off this field being honest.
  it("labels the bundled date as a release proxy, not the snapshot's own date", () => {
    expect(PSL_PROVENANCE.dateKind).toBe("release-proxy");
  });
});

describe("pslOutdated() — stale / undetermined / fresh", () => {
  it("cannot report fresh from a release-date proxy inside the window", () => {
    // 100 days after the proxy date, 180-day window. The true snapshot is that
    // date OR OLDER, so 100 is a MINIMUM age: it rules nothing out above.
    // Pre-LINK-elzuacby this returned `stale: false` — a freshness claim the
    // evidence never supported.
    const now = new Date("2026-04-11T00:00:00Z");
    expect(pslOutdated(180, { now, provenance: fixture })).toEqual({
      stale: null,
      ageDays: 100,
    });
  });

  it("reports fresh inside the window when the date is the snapshot's own", () => {
    // Same instant, same date — only the provenance kind differs. An exact date
    // makes 100 days the true age, which IS proof of freshness.
    const now = new Date("2026-04-11T00:00:00Z");
    expect(pslOutdated(180, { now, provenance: exactFixture })).toEqual({
      stale: false,
      ageDays: 100,
    });
  });

  it("reports stale when the snapshot is older than the window", () => {
    // 200 days after the snapshot, 180-day window. Sound from a proxy date too:
    // a MINIMUM age past the window is past the window.
    const now = new Date("2026-07-20T00:00:00Z");
    const got = pslOutdated(180, { now, provenance: fixture });
    expect(got.stale).toBe(true);
    expect(got.ageDays).toBe(200);
  });

  it("is exclusive at the exact boundary (age == maxAge is not yet stale)", () => {
    const now = new Date("2026-06-30T00:00:00Z"); // exactly 180 days later
    const got = pslOutdated(180, { now, provenance: fixture });
    expect(got.ageDays).toBe(180);
    // Not proven stale, and — from a proxy date — not proven fresh either.
    expect(got.stale).toBeNull();
    // The same boundary against an exact date: proven fresh, the strict `false`.
    expect(pslOutdated(180, { now, provenance: exactFixture }).stale).toBe(false);

    const oneMore = new Date("2026-07-01T00:00:00Z"); // 181 days
    expect(pslOutdated(180, { now: oneMore, provenance: fixture }).stale).toBe(true);
    expect(pslOutdated(180, { now: oneMore, provenance: exactFixture }).stale).toBe(true);
  });

  it("treats an unlabelled provenance record as a proxy, not as exact", () => {
    // Omitting `dateKind` must fail toward "undetermined": an unlabelled date is
    // the case we cannot vouch for, so it must not be able to claim freshness.
    const { dateKind: _dropped, ...unlabelled } = fixture;
    const now = new Date("2026-04-11T00:00:00Z");
    expect(pslOutdated(180, { now, provenance: unlabelled }).stale).toBeNull();
  });

  it("returns undetermined (null/null) when the snapshot date is unknown", () => {
    const unknown: PslProvenance = { ...fixture, pslListDate: null };
    expect(pslOutdated(180, { provenance: unknown })).toEqual({
      stale: null,
      ageDays: null,
    });
  });

  it("returns undetermined when the snapshot date is unparseable", () => {
    const bad: PslProvenance = { ...fixture, pslListDate: "not-a-date" };
    expect(pslOutdated(180, { provenance: bad })).toEqual({
      stale: null,
      ageDays: null,
    });
  });

  it("honors a custom freshness window", () => {
    const now = new Date("2026-02-01T00:00:00Z"); // 31 days later
    expect(pslOutdated(30, { now, provenance: fixture }).stale).toBe(true);
    // 31 days is inside a 60-day window, but from a proxy date that is a
    // minimum age — undetermined, not fresh.
    expect(pslOutdated(60, { now, provenance: fixture }).stale).toBeNull();
    expect(pslOutdated(60, { now, provenance: exactFixture }).stale).toBe(false);
  });

  it("rejects a non-positive or non-finite window", () => {
    expect(() => pslOutdated(0, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(-1, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(Number.NaN, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(Number.POSITIVE_INFINITY, { provenance: fixture })).toThrow(
      RangeError,
    );
  });

  it("is offline and pure — the REAL pinned record, on an injected clock", () => {
    // Anchored to the record's own capture date, not to the wall clock: the
    // suite must fail on a code change, never on the calendar rolling over or
    // on the next tldts bump (LINK-dvshjpik, LINK-elzuacby).
    const atCapture = new Date(`${PSL_PROVENANCE.retrievedAt}T00:00:00Z`);
    const captured = pslOutdated(180, { now: atCapture });
    // Not provably stale when it was captured — a pin must not ship already
    // past its own window. And not "fresh" either: the date is a proxy.
    expect(captured.stale).toBeNull();
    expect(captured.ageDays ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(180);

    // Far enough past the proxy date that even the LOWER bound clears the
    // window: staleness becomes provable. Derived from the record, so this
    // holds unchanged after a pin bump.
    const pinnedMs = Date.parse(`${PSL_PROVENANCE.pslListDate}T00:00:00Z`);
    const wellPast = new Date(pinnedMs + 400 * 86_400_000);
    expect(pslOutdated(180, { now: wellPast }).stale).toBe(true);
  });
});

describe("currentPslSnapshot() — the result-embedded metadata", () => {
  it("carries the provenance date and default-window staleness", () => {
    const now = new Date("2099-01-01T00:00:00Z"); // far future -> provably stale
    expect(currentPslSnapshot(now)).toEqual({
      date: PSL_PROVENANCE.pslListDate,
      stale: true,
    });
  });

  it("reports undetermined — never false — while the proxy bound is inside the window", () => {
    // The pinned record's date is a release proxy, so a result emitted the day
    // the record was captured says "unknown", not "fresh". This is the field
    // consumers read; `false` here would be a freshness claim linklint cannot
    // make offline (LINK-elzuacby).
    const snap = currentPslSnapshot(new Date(`${PSL_PROVENANCE.retrievedAt}T00:00:00Z`));
    expect(snap.date).toBe(PSL_PROVENANCE.pslListDate);
    expect(snap.stale).toBeNull();
  });
});
