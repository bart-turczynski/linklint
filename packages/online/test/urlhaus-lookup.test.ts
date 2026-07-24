import { inspectAsync, type EnrichmentReport, type InspectResult } from "linklint";
import { describe, expect, it } from "vitest";

import {
  canonicalizeUrl,
  createUrlhausEnricher,
  createUrlhausIndex,
  URLHAUS_SOURCE_ID,
  type UrlhausIndex,
  type UrlhausRecord,
  type UrlhausSnapshot,
  type UrlhausSnapshotMetadata,
  type UrlhausUrlStatus,
} from "../src/mirrors/index.js";

const NOW = "2026-07-24T00:00:00.000Z";

// --- Fixtures ---------------------------------------------------------------

function record(url: string, over: Partial<UrlhausRecord> = {}): UrlhausRecord {
  return {
    id: "3001",
    url,
    dateAdded: "2026-07-23T12:00:00.000Z",
    status: "online",
    lastOnline: "2026-07-24T00:00:00.000Z",
    threat: "malware_download",
    tags: ["exe"],
    reporter: "anonymous",
    ...over,
  };
}

function snapshot(
  records: UrlhausRecord[],
  over: Partial<UrlhausSnapshotMetadata> = {},
): UrlhausSnapshot {
  const metadata: UrlhausSnapshotMetadata = {
    source: URLHAUS_SOURCE_ID,
    version: "1.0.0",
    etag: '"v1"',
    lastModified: null,
    observedAt: "2026-07-23T23:00:00.000Z",
    // Fresh by default: expires one hour after NOW.
    expiresAt: "2026-07-24T01:00:00.000Z",
    recordCount: records.length,
    ...over,
  };
  return { metadata, records };
}

function indexOf(records: UrlhausRecord[], over: Partial<UrlhausSnapshotMetadata> = {}): UrlhausIndex {
  return createUrlhausIndex(snapshot(records, over));
}

/** Minimal InspectResult carrying only what the enricher reads. */
function fakeResult(input: string): InspectResult {
  return { input } as unknown as InspectResult;
}

async function run(
  input: string,
  index: UrlhausIndex | null,
): Promise<EnrichmentReport> {
  const enricher = createUrlhausEnricher({
    resolveIndex: () => index,
    now: () => new Date(NOW),
  });
  return (await enricher.enrich(fakeResult(input), { previousOutcomes: [] })) as EnrichmentReport;
}

// --- Canonicalization -------------------------------------------------------

describe("canonicalizeUrl", () => {
  it("lower-cases scheme and host, drops the default port and fragment", () => {
    expect(canonicalizeUrl("HTTP://Malware.Example:80/a.exe#frag")).toBe(
      "http://malware.example/a.exe",
    );
    expect(canonicalizeUrl("https://X.COM:443/p?q=1")).toBe("https://x.com/p?q=1");
  });

  it("preserves path and query exactly (case-sensitive)", () => {
    expect(canonicalizeUrl("http://x.com/A")).not.toBe(canonicalizeUrl("http://x.com/a"));
    expect(canonicalizeUrl("http://x.com/p?a=1&b=2")).toBe("http://x.com/p?a=1&b=2");
  });

  it("keeps a non-default port", () => {
    expect(canonicalizeUrl("http://x.com:8080/p")).toBe("http://x.com:8080/p");
  });

  it("converts an IDN host to its A-label", () => {
    expect(canonicalizeUrl("http://exämple.com/p")).toBe("http://xn--exmple-cua.com/p");
  });

  it("rejects non-http(s) and unparseable input", () => {
    expect(canonicalizeUrl("ftp://x.com/p")).toBeNull();
    expect(canonicalizeUrl("mailto:a@b.com")).toBeNull();
    expect(canonicalizeUrl("not a url")).toBeNull();
    expect(canonicalizeUrl("")).toBeNull();
  });
});

// --- Index exact lookup -----------------------------------------------------

describe("createUrlhausIndex", () => {
  const index = indexOf([record("http://malware.example/a.exe")]);

  it("matches an exact URL modulo canonicalization boundaries", () => {
    expect(index.lookup("http://malware.example/a.exe")?.id).toBe("3001");
    expect(index.lookup("HTTP://Malware.Example:80/a.exe")?.id).toBe("3001");
  });

  it("does not match a different path or query (exact-path mismatch)", () => {
    expect(index.lookup("http://malware.example/b.exe")).toBeNull();
    expect(index.lookup("http://malware.example/a.exe?x=1")).toBeNull();
  });

  it("never broadens to the host", () => {
    expect(index.lookup("http://malware.example/")).toBeNull();
    expect(index.lookup("http://malware.example")).toBeNull();
    expect(index.lookup("http://sub.malware.example/a.exe")).toBeNull();
  });

  it("drops records whose URL cannot be canonicalized", () => {
    const withBad = indexOf([record("ftp://x/p", { id: "bad" }), record("http://ok.example/p", { id: "ok" })]);
    expect(withBad.lookup("http://ok.example/p")?.id).toBe("ok");
  });
});

// --- Enricher ---------------------------------------------------------------

const HIT_URL = "http://malware.example/a.exe";

describe("createUrlhausEnricher", () => {
  it("emits evidence and a malware_url_listed finding for an online, fresh match", async () => {
    const report = await run(HIT_URL, indexOf([record(HIT_URL)]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence[0]?.type).toBe("urlhaus.match");
    expect(outcome.evidence[0]?.freshness.status).toBe("fresh");
    expect(outcome.findings.map((f) => f.code)).toEqual(["malware_url_listed"]);
    expect(outcome.findings[0]?.confidence).toBe(0.95);
    expect(outcome.evidence[0]?.payload).toMatchObject({ recordId: "3001", status: "online" });
  });

  it("emits evidence but no finding for an offline record", async () => {
    const report = await run(HIT_URL, indexOf([record(HIT_URL, { status: "offline" })]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence).toHaveLength(1);
    expect(outcome.findings).toEqual([]);
  });

  it("emits evidence but no finding when the snapshot is stale", async () => {
    const stale = indexOf([record(HIT_URL)], { expiresAt: "2026-07-23T00:00:00.000Z" });
    const report = await run(HIT_URL, stale);
    const outcome = report.outcomes[0]!;
    expect(outcome.evidence[0]?.freshness.status).toBe("stale");
    expect(outcome.findings).toEqual([]);
  });

  it("emits evidence but no finding when snapshot freshness is unknown", async () => {
    const noExpiry = indexOf([record(HIT_URL)], { expiresAt: null });
    const report = await run(HIT_URL, noExpiry);
    const outcome = report.outcomes[0]!;
    expect(outcome.evidence[0]?.freshness.status).toBe("unknown");
    expect(outcome.findings).toEqual([]);
  });

  it("returns a no-hit for a path/query mismatch", async () => {
    const report = await run("http://malware.example/other.exe", indexOf([record(HIT_URL)]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("no-hit");
    expect(outcome.evidence).toEqual([]);
    expect(outcome.findings).toEqual([]);
  });

  it("skips when no snapshot is loaded", async () => {
    const report = await run(HIT_URL, null);
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") expect(outcome.cause.code).toBe("urlhaus-no-snapshot");
  });

  it("skips a non-http(s) input that cannot be a URL-feed subject", async () => {
    const report = await run("mailto:a@b.com", indexOf([record(HIT_URL)]));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") {
      expect(outcome.cause.code).toBe("urlhaus-uncanonicalizable-input");
    }
  });

  it("matches a recently-added online record modulo input normalization", async () => {
    const index = indexOf([record(HIT_URL, { dateAdded: NOW, lastOnline: NOW })]);
    const report = await run("HTTP://Malware.Example:80/a.exe", index);
    const outcome = report.outcomes[0]!;
    expect(outcome.findings.map((f) => f.code)).toEqual(["malware_url_listed"]);
    expect(outcome.evidence[0]?.payload.dateAdded).toBe(NOW);
  });

  it.each<UrlhausUrlStatus>(["offline", "unknown"])(
    "does not score a %s record even when fresh",
    async (status) => {
      const report = await run(HIT_URL, indexOf([record(HIT_URL, { status })]));
      expect(report.outcomes[0]?.findings).toEqual([]);
    },
  );
});

// --- inspectAsync integration -----------------------------------------------

describe("createUrlhausEnricher — inspectAsync integration", () => {
  it("projects malware_url_listed into the result reasons with no network at check time", async () => {
    const index = indexOf([record(HIT_URL)]);
    const enricher = createUrlhausEnricher({ resolveIndex: () => index, now: () => new Date(NOW) });
    const result = await inspectAsync(HIT_URL, { enrichers: [enricher] });

    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain("malware_url_listed");
    expect(result.checksRun).toContain("reputation:urlhaus.mirror");
  });

  it("records a clean-URL miss as a completed no-hit, not a finding", async () => {
    const index = indexOf([record(HIT_URL)]);
    const enricher = createUrlhausEnricher({ resolveIndex: () => index, now: () => new Date(NOW) });
    const result = await inspectAsync("http://malware.example/not-listed.exe", {
      enrichers: [enricher],
    });
    expect(result.reasons.map((r) => r.code)).not.toContain("malware_url_listed");
  });
});
