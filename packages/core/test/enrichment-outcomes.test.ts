import { describe, expect, it } from "vitest";
import {
  ENRICHMENT_SCHEMA_VERSION,
  InMemoryEnrichmentCache,
  inspect,
  inspectAsync,
  isEnrichmentReport,
  type Enricher,
  type EnricherOutput,
  type EnrichmentLayer,
  type EnrichmentOutcome,
  type EnrichmentReport,
} from "../src/index.js";

/** K6 structured outcome/evidence contract fixtures; every adapter is no-network. */

const URL = "https://start.example/path";
const OBSERVED_AT = "2026-07-17T08:30:00.000Z";
const EXPIRES_AT = "2026-07-18T08:30:00.000Z";

const PROVENANCE = {
  kind: "declared",
  source: { name: "fixture.adapter", version: "1.0.0" },
  data: { name: "fixture.dataset", version: "2026-07-17" },
} as const;

const FRESHNESS = { status: "fresh", expiresAt: EXPIRES_AT } as const;

class StructuredEnricher implements Enricher {
  calls = 0;

  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    private readonly report: EnrichmentReport,
    readonly cacheTtlMs: number = 0,
  ) {}

  cacheKey(): string | null {
    return this.cacheTtlMs <= 0 ? null : "example";
  }

  async enrich(): Promise<EnrichmentReport> {
    this.calls += 1;
    return this.report;
  }
}

function report(outcomes: EnrichmentOutcome[]): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes };
}

function baseOutcome(
  sourceId: string,
  layer: EnrichmentLayer,
  subject: EnrichmentOutcome["subject"],
) {
  return {
    sourceId,
    layer,
    subject,
    observedAt: OBSERVED_AT,
    provenance: PROVENANCE,
    freshness: FRESHNESS,
  } as const;
}

function scoredFixtureReport(): EnrichmentReport {
  return report([
    {
      ...baseOutcome("boundary.fixture", "resolution", {
        kind: "host",
        value: "start.example",
      }),
      status: "success",
      evidence: [],
      findings: [{ code: "ip_private", detail: "validated fixture finding", confidence: 0.8 }],
    },
  ]);
}

function malformedBoundaryReport(
  kind: "confidence" | "code" | "layer" | "source" | "shape",
): EnrichmentReport {
  const candidate = JSON.parse(JSON.stringify(scoredFixtureReport())) as {
    schemaVersion: string;
    outcomes: Array<{
      sourceId: string;
      layer: string;
      status: string;
      cause?: unknown;
      findings: Array<{ code: string; confidence?: number }>;
    }>;
  };
  const outcome = candidate.outcomes[0]!;
  if (kind === "confidence") outcome.findings[0]!.confidence = 1.1;
  if (kind === "code") outcome.findings[0]!.code = "not_registered";
  if (kind === "layer") outcome.layer = "reputation";
  if (kind === "source") outcome.sourceId = "other.fixture";
  if (kind === "shape") outcome.cause = { code: "unexpected-on-success" };
  return candidate as EnrichmentReport;
}

describe("K6 — representative L/M/O structured evidence", () => {
  it("round-trips resolution, reputation, and static-content artifacts without losing attribution", async () => {
    const resolution = new StructuredEnricher(
      "redirect.fixture",
      "resolution",
      report([
        {
          ...baseOutcome("redirect.fixture", "resolution", { kind: "url", value: URL }),
          status: "success",
          evidence: [
            {
              type: "http.redirect",
              subject: { kind: "url", value: "https://destination.example/landing" },
              observedAt: OBSERVED_AT,
              provenance: PROVENANCE,
              freshness: FRESHNESS,
              payload: { statusCode: 302, hop: 1, location: "https://destination.example/landing" },
            },
          ],
          findings: [
            { code: "open_redirect_param", detail: "redirect destination diverges from input" },
          ],
        },
      ]),
    );
    const reputation = new StructuredEnricher(
      "rdap.fixture",
      "reputation",
      report([
        {
          ...baseOutcome("rdap.fixture", "reputation", {
            kind: "host",
            value: "start.example",
          }),
          status: "no-hit",
          evidence: [
            {
              type: "rdap.lookup",
              subject: { kind: "host", value: "start.example" },
              observedAt: OBSERVED_AT,
              provenance: PROVENANCE,
              freshness: FRESHNESS,
              payload: { matched: false, registrar: null },
            },
          ],
          findings: [],
        },
      ]),
    );
    const staticContent = new StructuredEnricher(
      "page-artifact.fixture",
      "reputation",
      report([
        {
          ...baseOutcome("page-artifact.fixture", "reputation", { kind: "url", value: URL }),
          status: "success",
          evidence: [
            {
              type: "page.form",
              subject: { kind: "url", value: URL },
              observedAt: OBSERVED_AT,
              provenance: PROVENANCE,
              freshness: FRESHNESS,
              payload: { acquiredAs: "static", executed: false, passwordFields: 1 },
            },
          ],
          findings: [
            {
              code: "credential_harvesting",
              detail: "static artifact contains a credential collection form",
              confidence: 0.75,
            },
          ],
        },
      ]),
    );

    const result = await inspectAsync(URL, {
      enrichers: [resolution, reputation, staticContent],
    });
    const serialized = JSON.stringify(result.enrichment);
    const roundTripped: unknown = JSON.parse(serialized);

    expect(result.schemaVersion).toBe("1.8");
    expect(result.enrichment?.schemaVersion).toBe("1.0");
    expect(isEnrichmentReport(roundTripped)).toBe(true);
    expect(roundTripped).toEqual(result.enrichment);
    expect(result.enrichment?.outcomes.map((item) => item.status)).toEqual([
      "success",
      "no-hit",
      "success",
    ]);
    expect(result.enrichment?.outcomes[0]?.observedAt).toBe(OBSERVED_AT);
    expect(result.enrichment?.outcomes[0]?.freshness.expiresAt).toBe(EXPIRES_AT);
    expect(result.enrichment?.outcomes[0]?.provenance).toEqual(PROVENANCE);
    expect(result.enrichment?.outcomes[2]?.evidence[0]?.payload).toEqual({
      acquiredAs: "static",
      executed: false,
      passwordFields: 1,
    });
    expect(result.reasons.map((reason) => reason.code)).toEqual(
      expect.arrayContaining(["open_redirect_param", "credential_harvesting"]),
    );
    expect(result.confidence).toBe(0.75);
  });
});

describe("K6 — outcome status and identity validation", () => {
  it("keeps no-hit and skipped sources machine-distinguishable", async () => {
    const noHit: EnrichmentOutcome = {
      ...baseOutcome("feed.fixture", "reputation", { kind: "host", value: "start.example" }),
      status: "no-hit",
      evidence: [],
      findings: [],
    };
    const skipped: EnrichmentOutcome = {
      ...baseOutcome("consent.fixture", "resolution", { kind: "url", value: URL }),
      status: "skipped",
      evidence: [],
      findings: [],
      cause: { code: "consent-required", retryable: false },
    };

    const result = await inspectAsync(URL, {
      enrichers: [
        new StructuredEnricher("feed.fixture", "reputation", report([noHit])),
        new StructuredEnricher("consent.fixture", "resolution", report([skipped])),
      ],
    });

    expect(result.enrichment?.outcomes).toEqual([noHit, skipped]);
    expect(result.checksRun).toContain("reputation:feed.fixture");
    expect(result.checksSkipped).not.toContain("reputation:feed.fixture");
    expect(result.checksSkipped).toContain("resolution:consent.fixture");
    expect(result.checksRun).not.toContain("resolution:consent.fixture");
  });

  it.each([
    ["source", "other.fixture", "resolution"],
    ["layer", "dns.fixture", "reputation"],
  ] as const)("rejects a structured report whose %s identity does not match the enricher", async (_label, sourceId, layer) => {
    const mismatched = report([
      {
        ...baseOutcome(sourceId, layer, { kind: "host", value: "start.example" }),
        status: "success",
        evidence: [
          {
            type: "dns.answer",
            subject: { kind: "host", value: "start.example" },
            observedAt: OBSERVED_AT,
            provenance: PROVENANCE,
            freshness: FRESHNESS,
            payload: { addresses: ["192.0.2.1"] },
          },
        ],
        findings: [],
      },
    ]);
    const enricher = new StructuredEnricher("dns.fixture", "resolution", mismatched);

    const result = await inspectAsync(URL, { enrichers: [enricher] });
    const outcome = result.enrichment?.outcomes[0];

    expect(outcome?.status).toBe("failure");
    expect(outcome?.provenance.kind).toBe("unavailable");
    expect(outcome?.status === "failure" ? outcome.cause.code : null).toBe("invalid-output");
    expect(result.checksSkipped).toContain("resolution:dns.fixture");
  });

  it("turns a thrown source into an attributed failure rather than a clean result", async () => {
    const enricher: Enricher = {
      id: "rdap.fixture",
      layer: "reputation",
      async enrich(): Promise<EnricherOutput> {
        throw new Error("fixture failure");
      },
    };

    const result = await inspectAsync(URL, { enrichers: [enricher] });
    const outcome = result.enrichment?.outcomes[0];

    expect(outcome?.status).toBe("failure");
    expect(outcome?.sourceId).toBe("rdap.fixture");
    expect(outcome?.layer).toBe("reputation");
    expect(outcome?.status === "failure" ? outcome.cause.code : null).toBe("source-error");
    expect(result.checksSkipped).toContain("reputation:rdap.fixture");
  });

  it.each(["confidence", "code", "layer", "source", "shape"] as const)(
    "rejects malformed fresh %s data at the public enricher boundary",
    async (kind) => {
      const malformed = malformedBoundaryReport(kind);
      const enricher = new StructuredEnricher(
        "boundary.fixture",
        "resolution",
        malformed,
      );

      expect(
        isEnrichmentReport(malformed, {
          sourceId: "boundary.fixture",
          layer: "resolution",
        }),
      ).toBe(false);
      const result = await inspectAsync(URL, { enrichers: [enricher] });
      expect(
        result.enrichment?.outcomes.some(
          (outcome) =>
            outcome.status === "failure" && outcome.cause.code === "invalid-output",
        ),
      ).toBe(true);
      expect(result.reasons.some((reason) => reason.detail === "validated fixture finding"))
        .toBe(false);
    },
  );

  it.each(["confidence", "code", "layer", "source", "shape"] as const)(
    "rejects corrupted cached %s data before it can affect a result",
    async (kind) => {
      let providerCalls = 0;
      const enricher: Enricher = {
        id: "boundary.fixture",
        layer: "resolution",
        cacheKey: () => "start.example",
        cacheTtlMs: 1000,
        async enrich() {
          providerCalls += 1;
          return scoredFixtureReport();
        },
      };
      const result = await inspectAsync(URL, {
        cache: {
          get: () => malformedBoundaryReport(kind),
          set() {},
        },
        enrichers: [enricher],
      });

      expect(providerCalls).toBe(0);
      expect(
        result.enrichment?.outcomes.some(
          (outcome) =>
            outcome.status === "failure" &&
            outcome.cause.code === "invalid-cached-output",
        ),
      ).toBe(true);
      expect(result.reasons.some((reason) => reason.detail === "validated fixture finding"))
        .toBe(false);
    },
  );
});

describe("K6 — compatibility, caching, and offline invariants", () => {
  it("keeps legacy findings working while marking their provenance incomplete", async () => {
    const legacy: Enricher = {
      id: "legacy.fixture",
      layer: "resolution",
      async enrich() {
        return [{ code: "ip_private", detail: "legacy fixture finding" }];
      },
    };

    const result = await inspectAsync(URL, { enrichers: [legacy] });
    const outcome = result.enrichment?.outcomes[0];

    expect(outcome?.status).toBe("success");
    expect(outcome?.provenance).toEqual({
      kind: "legacy-incomplete",
      source: null,
      data: null,
    });
    expect(result.reasons.map((reason) => reason.code)).toContain("ip_private");
  });

  it("preserves structured observation time/provenance through the cache", async () => {
    const structured = new StructuredEnricher(
      "dns.fixture",
      "resolution",
      report([
        {
          ...baseOutcome("dns.fixture", "resolution", {
            kind: "host",
            value: "start.example",
          }),
          status: "no-hit",
          evidence: [],
          findings: [],
        },
      ]),
      1000,
    );
    const cache = new InMemoryEnrichmentCache();

    const first = await inspectAsync(URL, { cache, enrichers: [structured] });
    const second = await inspectAsync(URL, { cache, enrichers: [structured] });

    expect(structured.calls).toBe(1);
    expect(second.enrichment).toEqual(first.enrichment);
    expect(second.enrichment?.outcomes[0]?.observedAt).toBe(OBSERVED_AT);
    expect(second.enrichment?.outcomes[0]?.provenance).toEqual(PROVENANCE);
  });

  it("leaves synchronous output and the no-enricher async path identical and outcome-free", async () => {
    const sync = inspect(URL);
    const asyncWithoutWork = await inspectAsync(URL);

    expect(asyncWithoutWork).toEqual(sync);
    expect("enrichment" in sync).toBe(false);
    expect("enrichment" in asyncWithoutWork).toBe(false);
  });
});
