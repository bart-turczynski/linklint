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
 */

// A fixed snapshot date so the fresh/stale boundary is exact and deterministic.
const fixture: PslProvenance = {
  tldtsVersion: "0.0.0",
  pslListDate: "2026-01-01",
  retrievedAt: "2026-01-01",
};

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
});

describe("pslOutdated() — fresh / stale / unknown", () => {
  it("reports fresh when the snapshot is within the window", () => {
    // 100 days after the snapshot, 180-day window.
    const now = new Date("2026-04-11T00:00:00Z");
    expect(pslOutdated(180, { now, provenance: fixture })).toEqual({
      stale: false,
      ageDays: 100,
    });
  });

  it("reports stale when the snapshot is older than the window", () => {
    // 200 days after the snapshot, 180-day window.
    const now = new Date("2026-07-20T00:00:00Z");
    const got = pslOutdated(180, { now, provenance: fixture });
    expect(got.stale).toBe(true);
    expect(got.ageDays).toBe(200);
  });

  it("is exclusive at the exact boundary (age == maxAge is still fresh)", () => {
    const now = new Date("2026-06-30T00:00:00Z"); // exactly 180 days later
    const got = pslOutdated(180, { now, provenance: fixture });
    expect(got.ageDays).toBe(180);
    expect(got.stale).toBe(false);

    const oneMore = new Date("2026-07-01T00:00:00Z"); // 181 days
    expect(pslOutdated(180, { now: oneMore, provenance: fixture }).stale).toBe(true);
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
    expect(pslOutdated(60, { now, provenance: fixture }).stale).toBe(false);
  });

  it("rejects a non-positive or non-finite window", () => {
    expect(() => pslOutdated(0, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(-1, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(Number.NaN, { provenance: fixture })).toThrow(RangeError);
    expect(() => pslOutdated(Number.POSITIVE_INFINITY, { provenance: fixture })).toThrow(
      RangeError,
    );
  });

  it("is offline and pure — the real pinned snapshot is not stale today", () => {
    // The pinned tldts@7.4.3 snapshot (2026-06-15) must be fresh at build time;
    // if this ever flips, the pin is overdue for a bump (and the freshness-corpus
    // test guards the concrete harm).
    expect(pslOutdated().stale).toBe(false);
  });
});

describe("currentPslSnapshot() — the result-embedded metadata", () => {
  it("carries the provenance date and default-window staleness", () => {
    const now = new Date("2099-01-01T00:00:00Z"); // far future -> stale
    expect(currentPslSnapshot(now)).toEqual({
      date: PSL_PROVENANCE.pslListDate,
      stale: true,
    });
  });

  it("reflects a fresh snapshot at the current time", () => {
    const snap = currentPslSnapshot();
    expect(snap.date).toBe(PSL_PROVENANCE.pslListDate);
    expect(snap.stale).toBe(false);
  });
});
