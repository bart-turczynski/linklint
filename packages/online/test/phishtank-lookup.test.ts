import { inspectAsync, type EnrichmentReport, type InspectResult } from "linklint";
import { describe, expect, it } from "vitest";

import {
  createPhishTankEnricher,
  createPhishTankIndex,
  PHISHTANK_SOURCE_ID,
  type PhishTankIndex,
  type PhishTankRecord,
  type PhishTankSnapshot,
  type PhishTankSnapshotMetadata,
} from "../src/mirrors/index.js";

const NOW = "2026-07-24T00:00:00.000Z";
const HIT_URL = "http://evil.example/login";

// --- Fixtures ---------------------------------------------------------------

function record(url: string, over: Partial<PhishTankRecord> = {}): PhishTankRecord {
  return {
    phishId: "8000001",
    url,
    detailUrl: "http://www.phishtank.com/phish_detail.php?phish_id=8000001",
    submissionTime: "2026-07-20T12:00:00.000Z",
    verified: true,
    verificationTime: "2026-07-20T13:00:00.000Z",
    online: true,
    target: "PayPal",
    ...over,
  };
}

function snapshot(
  records: PhishTankRecord[],
  over: Partial<PhishTankSnapshotMetadata> = {},
): PhishTankSnapshot {
  const metadata: PhishTankSnapshotMetadata = {
    source: PHISHTANK_SOURCE_ID,
    version: "1.0.0",
    etag: '"p1"',
    lastModified: null,
    observedAt: "2026-07-23T23:00:00.000Z",
    expiresAt: "2026-07-24T01:00:00.000Z",
    recordCount: records.length,
    ...over,
  };
  return { metadata, records };
}

function indexOf(
  records: PhishTankRecord[],
  over: Partial<PhishTankSnapshotMetadata> = {},
): PhishTankIndex {
  return createPhishTankIndex(snapshot(records, over));
}

function fakeResult(input: string): InspectResult {
  return { input } as unknown as InspectResult;
}

async function run(input: string, index: PhishTankIndex | null): Promise<EnrichmentReport> {
  const enricher = createPhishTankEnricher({
    resolveIndex: () => index,
    now: () => new Date(NOW),
  });
  return (await enricher.enrich(fakeResult(input), { previousOutcomes: [] })) as EnrichmentReport;
}

// --- Index exact lookup -----------------------------------------------------

describe("createPhishTankIndex", () => {
  const index = indexOf([record(HIT_URL)]);

  it("matches an exact URL modulo canonicalization boundaries", () => {
    expect(index.lookup(HIT_URL)?.phishId).toBe("8000001");
    expect(index.lookup("HTTP://Evil.Example:80/login")?.phishId).toBe("8000001");
  });

  it("does not match a different path/query and never broadens to the host", () => {
    expect(index.lookup("http://evil.example/signin")).toBeNull();
    expect(index.lookup("http://evil.example/login?x=1")).toBeNull();
    expect(index.lookup("http://evil.example/")).toBeNull();
  });
});

// --- Enricher ---------------------------------------------------------------

describe("createPhishTankEnricher", () => {
  it("emits evidence and a verified_phish_listed finding for a verified, online, fresh match", async () => {
    const report = await run(HIT_URL, indexOf([record(HIT_URL)]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence[0]?.type).toBe("phishtank.match");
    expect(outcome.evidence[0]?.payload).toMatchObject({
      phishId: "8000001",
      verified: true,
      online: true,
      target: "PayPal",
    });
    expect(outcome.findings.map((f) => f.code)).toEqual(["verified_phish_listed"]);
    expect(outcome.findings[0]?.confidence).toBe(0.95);
  });

  it("emits evidence but no finding for an unverified record", async () => {
    const report = await run(HIT_URL, indexOf([record(HIT_URL, { verified: false })]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence).toHaveLength(1);
    expect(outcome.findings).toEqual([]);
  });

  it("emits evidence but no finding for an offline record", async () => {
    const report = await run(HIT_URL, indexOf([record(HIT_URL, { online: false })]));
    expect(report.outcomes[0]?.findings).toEqual([]);
  });

  it("emits evidence but no finding when the snapshot is stale", async () => {
    const stale = indexOf([record(HIT_URL)], { expiresAt: "2026-07-23T00:00:00.000Z" });
    const report = await run(HIT_URL, stale);
    const outcome = report.outcomes[0]!;
    expect(outcome.evidence[0]?.freshness.status).toBe("stale");
    expect(outcome.findings).toEqual([]);
  });

  it("returns a no-hit for a removed / false-positive-corrected URL (absent from snapshot)", async () => {
    const report = await run(HIT_URL, indexOf([record("http://other.example/x")]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("no-hit");
    expect(outcome.evidence).toEqual([]);
    expect(outcome.findings).toEqual([]);
  });

  it("returns a no-hit for an exact-path mismatch", async () => {
    const report = await run("http://evil.example/elsewhere", indexOf([record(HIT_URL)]));
    expect(report.outcomes[0]?.status).toBe("no-hit");
  });

  it("skips when no snapshot is loaded", async () => {
    const report = await run(HIT_URL, null);
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") expect(outcome.cause.code).toBe("phishtank-no-snapshot");
  });

  it("skips a non-http(s) input", async () => {
    const report = await run("mailto:a@b.com", indexOf([record(HIT_URL)]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") {
      expect(outcome.cause.code).toBe("phishtank-uncanonicalizable-input");
    }
  });
});

// --- inspectAsync integration -----------------------------------------------

describe("createPhishTankEnricher — inspectAsync integration", () => {
  it("projects verified_phish_listed into the result reasons with no network at check time", async () => {
    const index = indexOf([record(HIT_URL)]);
    const enricher = createPhishTankEnricher({ resolveIndex: () => index, now: () => new Date(NOW) });
    const result = await inspectAsync(HIT_URL, { enrichers: [enricher] });

    expect(result.reasons.map((r) => r.code)).toContain("verified_phish_listed");
    expect(result.checksRun).toContain("reputation:phishtank.mirror");
  });

  it("records a clean-URL miss as a completed no-hit, not a finding", async () => {
    const index = indexOf([record(HIT_URL)]);
    const enricher = createPhishTankEnricher({ resolveIndex: () => index, now: () => new Date(NOW) });
    const result = await inspectAsync("http://evil.example/not-listed", { enrichers: [enricher] });
    expect(result.reasons.map((r) => r.code)).not.toContain("verified_phish_listed");
  });
});
