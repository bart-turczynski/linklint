import { describe, expect, it } from "vitest";

import { ENRICHMENT_SCHEMA_VERSION, inspectAsync } from "linklint";
import type { EnrichmentEvidence, EnrichmentOutcome } from "linklint";

import {
  DIVERGENCE_PROBE_SOURCE_ID,
  EMBEDDED_WRAPPER_SOURCE_ID,
  REDIRECT_CHAIN_SOURCE_ID,
  createDivergenceProbeEnricher,
  createEmbeddedWrapperEnricher,
  createRedirectChainEnricher,
  decodeEmbeddedWrapper,
} from "../src/resolution/index.js";
import { createSafeTransport } from "../src/transport/index.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../src/testing/index.js";

import {
  RESOLUTION_CORPUS,
  type ChallengeRow,
  type DivergenceRow,
  type MimeRow,
  type ResolutionCorpusRow,
  type ResolutionFamily,
  type ResponseStep,
  type WrapperRow,
} from "./corpus/resolution-corpus.js";

const PUBLIC_ADDRESS = "93.184.216.34";
const START_TIME = "2026-07-17T12:00:00.000Z";

/**
 * L2 heuristics are deterministic and exact-by-construction, so the corpus is
 * expected to classify every row correctly. The threshold is stated as a named
 * constant so a future precision/recall regression (a new false positive or a
 * missed true positive) fails this gate loudly rather than silently eroding.
 * Deterministic redirect/refresh MECHANICS are NOT precision/recall'd here —
 * they are pinned exhaustively by the per-enricher vitest suites and the
 * Cucumber features, per the issue.
 */
const RESOLUTION_PR_THRESHOLD = 1.0;

const FAMILIES: readonly ResolutionFamily[] = ["wrapper", "divergence", "challenge", "mime"];

// ── Transport fixture harness (mirrors redirect-chain/divergence tests) ─────
function connection(id: string, url: string): FixtureConnection {
  const parsed = new URL(url);
  const port = parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
  return {
    id,
    protocol: parsed.protocol as "http:" | "https:",
    remoteAddress: PUBLIC_ADDRESS,
    remotePort: port,
    ...(parsed.protocol === "https:"
      ? { tls: { authorized: true, serverName: parsed.hostname, peerDnsNames: [parsed.hostname] } }
      : {}),
  };
}

function scriptFor(steps: readonly ResponseStep[]): TransportFixtureScript {
  return {
    startTime: START_TIME,
    resolver: steps.map((step) => ({
      hostname: new URL(step.url).hostname,
      outcome: { value: [{ address: PUBLIC_ADDRESS, family: 4 as const, ttlSeconds: 60 }] },
    })),
    connector: steps.map((step, index) => {
      const parsed = new URL(step.url);
      const port =
        parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
      return {
        expect: {
          protocol: parsed.protocol as "http:" | "https:",
          hostname: parsed.hostname,
          address: PUBLIC_ADDRESS,
          port,
          ...(parsed.protocol === "https:" ? { serverName: parsed.hostname } : {}),
        },
        outcome: { value: connection(`c${index + 1}`, step.url) },
      };
    }),
    http: steps.map((step, index) => ({
      expect: { connectionId: `c${index + 1}`, url: step.url, method: step.method ?? "GET" },
      outcome: {
        value: {
          status: step.status,
          ...(step.headers === undefined ? {} : { headers: step.headers }),
          ...(step.body === undefined ? {} : { body: step.body }),
        },
      },
    })),
  };
}

function fixtureTransport(steps: readonly ResponseStep[]) {
  const harness = new TransportFixtureHarness(scriptFor(steps));
  const transport = createSafeTransport({
    resolver: harness.resolver,
    connector: harness.connector,
    http: harness.http,
    clock: harness.clock,
  });
  const authorize = async ({ url }: { url: string }) => ({
    kind: "destination-fetch" as const,
    url,
  });
  return { harness, transport, authorize, now: () => harness.clock.now() };
}

function allEvidence(
  result: Awaited<ReturnType<typeof inspectAsync>>,
): EnrichmentEvidence[] {
  return (result.enrichment?.outcomes ?? []).flatMap((outcome) => outcome.evidence);
}

function findEvidence(
  result: Awaited<ReturnType<typeof inspectAsync>>,
  type: string,
): EnrichmentEvidence | undefined {
  return allEvidence(result).find((item) => item.type === type);
}

// ── Deterministic classifiers over the corpus (predicted positive?) ──────────
function wrapperPredictedPositive(row: WrapperRow): boolean {
  return decodeEmbeddedWrapper(row.input).status === "decoded";
}

async function divergencePredictedPositive(row: DivergenceRow): Promise<boolean> {
  const { harness, transport, authorize, now } = fixtureTransport(row.steps);
  const enricher = createDivergenceProbeEnricher({ transport, authorize, now });
  const result = await inspectAsync(row.url, { enrichers: [enricher] });
  harness.assertExhausted();
  const payload = findEvidence(result, "resolution.divergence")?.payload as
    | { divergent?: boolean }
    | undefined;
  return payload?.divergent === true;
}

async function challengePredictedPositive(row: ChallengeRow): Promise<boolean> {
  const { harness, transport, authorize, now } = fixtureTransport(row.steps);
  const enricher = createDivergenceProbeEnricher({ transport, authorize, now });
  const result = await inspectAsync(row.url, { enrichers: [enricher] });
  harness.assertExhausted();
  return (result.enrichment?.outcomes ?? []).some(
    (outcome) => outcome.cause?.code === "challenge-gate",
  );
}

async function mimePredictedPositive(row: MimeRow): Promise<boolean> {
  const { harness, transport, authorize, now } = fixtureTransport([row.step]);
  const enricher = createRedirectChainEnricher({
    transport,
    authorize,
    now,
    ...(row.method === undefined ? {} : { method: row.method }),
  });
  const result = await inspectAsync(row.url, { enrichers: [enricher] });
  harness.assertExhausted();
  const payload = findEvidence(result, "resolution.mime-evidence")?.payload as
    | { active?: boolean }
    | undefined;
  return payload?.active === true;
}

async function predictedPositive(row: ResolutionCorpusRow): Promise<boolean> {
  switch (row.family) {
    case "wrapper":
      return wrapperPredictedPositive(row);
    case "divergence":
      return divergencePredictedPositive(row);
    case "challenge":
      return challengePredictedPositive(row);
    case "mime":
      return mimePredictedPositive(row);
  }
}

interface Prediction {
  readonly predicted: boolean;
  readonly actual: boolean;
}

function precisionRecall(predictions: readonly Prediction[]): {
  precision: number;
  recall: number;
} {
  const tp = predictions.filter((p) => p.predicted && p.actual).length;
  const fp = predictions.filter((p) => p.predicted && !p.actual).length;
  const fn = predictions.filter((p) => !p.predicted && p.actual).length;
  return {
    precision: tp + fp === 0 ? 1 : tp / (tp + fp),
    recall: tp + fn === 0 ? 1 : tp / (tp + fn),
  };
}

describe("L2 resolution heuristic precision/recall", () => {
  it.each(FAMILIES)(
    "%s family classifies every corpus row at or above the P/R threshold",
    async (family) => {
      const rows = RESOLUTION_CORPUS.filter((row) => row.family === family);

      // A P/R gate with only positives (or only negatives) is meaningless.
      expect(rows.some((row) => row.label === "positive")).toBe(true);
      expect(rows.some((row) => row.label === "negative")).toBe(true);

      const predictions: Prediction[] = [];
      for (const row of rows) {
        predictions.push({
          predicted: await predictedPositive(row),
          actual: row.label === "positive",
        });
      }

      const { precision, recall } = precisionRecall(predictions);
      expect(precision).toBeGreaterThanOrEqual(RESOLUTION_PR_THRESHOLD);
      expect(recall).toBeGreaterThanOrEqual(RESOLUTION_PR_THRESHOLD);
    },
  );

  it("pins the exact wrapper classification for every wrapper row", () => {
    const rows = RESOLUTION_CORPUS.filter(
      (row): row is WrapperRow => row.family === "wrapper",
    );
    for (const row of rows) {
      const decoded = decodeEmbeddedWrapper(row.input);
      expect(decoded.status, row.name).toBe(row.expected.status);
      if (row.expected.status === "decoded" && decoded.status === "decoded") {
        expect(decoded.vendor, row.name).toBe(row.expected.vendor);
        expect(decoded.destinationUrl, row.name).toBe(row.expected.destinationUrl);
        expect(decoded.format, row.name).toBe(row.expected.format);
      } else if (
        (row.expected.status === "unsupported" || row.expected.status === "malformed") &&
        (decoded.status === "unsupported" || decoded.status === "malformed")
      ) {
        expect(decoded.vendor, row.name).toBe(row.expected.vendor);
      }
    }
  });
});

// ── Structured-evidence + checks contract pins ──────────────────────────────
describe("L2 structured-evidence and checks contract", () => {
  it("pins the enrichment schema version", () => {
    expect(ENRICHMENT_SCHEMA_VERSION).toBe("1.0");
  });

  it("redirect-chain: schema, evidence types, and checksRun token on success", async () => {
    const start = "https://origin.example/start";
    const next = "https://origin.example/landing";
    const { harness, transport, authorize, now } = fixtureTransport([
      { url: start, status: 302, headers: { location: next } },
      { url: next, status: 200, headers: { "content-type": "text/plain" }, body: "ok" },
    ]);
    const result = await inspectAsync(start, {
      enrichers: [createRedirectChainEnricher({ transport, authorize, now })],
    });
    harness.assertExhausted();

    expect(result.enrichment?.schemaVersion).toBe(ENRICHMENT_SCHEMA_VERSION);
    const types = new Set(allEvidence(result).map((item) => item.type));
    expect(types).toContain("resolution.chain-hop");
    expect(types).toContain("resolution.mime-evidence");
    expect(result.checksRun).toContain(`resolution:${REDIRECT_CHAIN_SOURCE_ID}`);
  });

  it("divergence-probe: schema, evidence types, and checksRun token on success", async () => {
    const url = "https://origin.example/page";
    const same: ResponseStep = { url, status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body: "<html><body>x</body></html>" };
    const { harness, transport, authorize, now } = fixtureTransport([same, same]);
    const result = await inspectAsync(url, {
      enrichers: [createDivergenceProbeEnricher({ transport, authorize, now })],
    });
    harness.assertExhausted();

    expect(result.enrichment?.schemaVersion).toBe(ENRICHMENT_SCHEMA_VERSION);
    const types = new Set(allEvidence(result).map((item) => item.type));
    expect(types).toContain("resolution.variant-response");
    expect(types).toContain("resolution.divergence");
    expect(result.checksRun).toContain(`resolution:${DIVERGENCE_PROBE_SOURCE_ID}`);
  });

  it("embedded-wrapper: schema, evidence type, and checksRun token on success", async () => {
    const input =
      `https://nam01.safelinks.protection.outlook.com/?url=${encodeURIComponent("https://example.com/a")}` +
      "&data=05%7C01&reserved=0";
    const result = await inspectAsync(input, {
      enrichers: [createEmbeddedWrapperEnricher({ now: () => new Date(START_TIME) })],
    });

    expect(result.enrichment?.schemaVersion).toBe(ENRICHMENT_SCHEMA_VERSION);
    const types = new Set(allEvidence(result).map((item) => item.type));
    expect(types).toContain("wrapper.decode");
    expect(result.checksRun).toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
  });
});

// ── Partial / incomplete pin: every non-success carries a machine-readable cause ──
describe("L2 partial/incomplete outcomes carry machine-readable causes", () => {
  async function redirectChain(
    steps: readonly ResponseStep[],
    overrides: Partial<Parameters<typeof createRedirectChainEnricher>[0]> = {},
  ): Promise<EnrichmentOutcome[]> {
    const { harness, transport, authorize, now } = fixtureTransport(steps);
    const result = await inspectAsync(steps[0]!.url, {
      enrichers: [createRedirectChainEnricher({ transport, authorize, now, ...overrides })],
    });
    harness.assertExhausted();
    return result.enrichment?.outcomes ?? [];
  }

  it("never emits a silent non-success outcome and covers the required cause codes", async () => {
    const start = "https://origin.example/start";
    const outcomes: EnrichmentOutcome[] = [];

    // redirect-loop: self-referential Location.
    outcomes.push(...(await redirectChain([{ url: start, status: 302, headers: { location: "/start" } }])));

    // hop-limit: a redirect capped at one hop.
    outcomes.push(
      ...(await redirectChain([{ url: start, status: 302, headers: { location: "/next" } }], {
        maxHops: 1,
      })),
    );

    // prohibited-address: L0 blocks a cloud-metadata address before HTTP.
    {
      const harness = new TransportFixtureHarness({
        startTime: START_TIME,
        resolver: [
          {
            hostname: "origin.example",
            outcome: { value: [{ address: "169.254.169.254", family: 4, ttlSeconds: 1 }] },
          },
        ],
      });
      const transport = createSafeTransport({
        resolver: harness.resolver,
        connector: harness.connector,
        http: harness.http,
        clock: harness.clock,
      });
      const result = await inspectAsync(start, {
        enrichers: [
          createRedirectChainEnricher({
            transport,
            authorize: ({ url }) => ({ kind: "destination-fetch", url }),
            now: () => harness.clock.now(),
          }),
        ],
      });
      harness.assertExhausted();
      outcomes.push(...(result.enrichment?.outcomes ?? []));
    }

    // challenge-gate: a divergence-probe variant hits a challenge marker.
    {
      const url = "https://origin.example/page";
      const { harness, transport, authorize, now } = fixtureTransport([
        { url, status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body: "<html><body>real</body></html>" },
        {
          url,
          status: 403,
          headers: { "content-type": "text/html; charset=utf-8" },
          body: '<html><head><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script></head></html>',
        },
      ]);
      const result = await inspectAsync(url, {
        enrichers: [createDivergenceProbeEnricher({ transport, authorize, now })],
      });
      harness.assertExhausted();
      outcomes.push(...(result.enrichment?.outcomes ?? []));
    }

    const nonSuccess = outcomes.filter((outcome) => outcome.status !== "success");
    expect(nonSuccess.length).toBeGreaterThan(0);
    for (const outcome of nonSuccess) {
      expect(outcome.status === "skipped" || outcome.status === "failure").toBe(true);
      expect(typeof outcome.cause?.code).toBe("string");
      expect(outcome.cause?.code.length ?? 0).toBeGreaterThan(0);
    }
    const codes = new Set(nonSuccess.map((outcome) => outcome.cause?.code));
    for (const required of ["redirect-loop", "hop-limit", "prohibited-address", "challenge-gate"]) {
      expect(codes, `missing cause ${required}`).toContain(required);
    }
  });

  it("records a MIME incomplete evidence record with a machine-readable cause on a HEAD hop", async () => {
    const start = "https://origin.example/asset";
    const { harness, transport, authorize, now } = fixtureTransport([
      { url: start, method: "HEAD", status: 200, headers: { "content-type": "image/png" }, body: "<script>x</script>" },
    ]);
    const result = await inspectAsync(start, {
      enrichers: [createRedirectChainEnricher({ transport, authorize, now, method: "HEAD" })],
    });
    harness.assertExhausted();

    const record = findEvidence(result, "resolution.mime-evidence");
    expect(record?.payload).toMatchObject({ status: "incomplete", cause: "no-body" });
  });
});

// ── Privacy-disclosure pin ──────────────────────────────────────────────────
describe("L2 privacy disclosure documentation", () => {
  it("documents every L2 resolution source id under the privacy disclosure section", async () => {
    const { readFileSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const here = dirname(fileURLToPath(import.meta.url));
    const docPath = join(here, "..", "..", "..", "docs", "redirect-chain-resolution.md");
    const doc = readFileSync(docPath, "utf8");

    const heading = "## Privacy disclosure (Layer 2 sources)";
    const headingIndex = doc.indexOf(heading);
    expect(headingIndex, "missing privacy disclosure heading").toBeGreaterThanOrEqual(0);
    const section = doc.slice(headingIndex);

    for (const sourceId of [
      REDIRECT_CHAIN_SOURCE_ID,
      DIVERGENCE_PROBE_SOURCE_ID,
      EMBEDDED_WRAPPER_SOURCE_ID,
    ]) {
      expect(section, `missing ${sourceId} in disclosure`).toContain(sourceId);
    }
  });
});
