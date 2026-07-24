import { describe, expect, it, vi } from "vitest";

import { inspect, inspectAsync } from "linklint";

import {
  DIVERGENCE_PROBE_SOURCE_ID,
  createDivergenceProbeEnricher,
} from "../src/resolution/index.js";
import { createSafeTransport } from "../src/transport/index.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../src/testing/index.js";

const PUBLIC_ADDRESS = "93.184.216.34";
const START_TIME = "2026-07-17T12:00:00.000Z";

interface ResponseStep {
  readonly url: string;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: string;
  readonly method?: "GET" | "HEAD";
}

function connection(id: string, url: string): FixtureConnection {
  const parsed = new URL(url);
  const port = parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
  return {
    id,
    protocol: parsed.protocol as "http:" | "https:",
    remoteAddress: PUBLIC_ADDRESS,
    remotePort: port,
    ...(parsed.protocol === "https:"
      ? {
          tls: {
            authorized: true,
            serverName: parsed.hostname,
            peerDnsNames: [parsed.hostname],
          },
        }
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
      const port = parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
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
      expect: {
        connectionId: `c${index + 1}`,
        url: step.url,
        method: step.method ?? "GET",
      },
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

function fixtureEnricher(
  steps: readonly ResponseStep[],
  overrides: Partial<Parameters<typeof createDivergenceProbeEnricher>[0]> = {},
) {
  const harness = new TransportFixtureHarness(scriptFor(steps));
  const transport = createSafeTransport({
    resolver: harness.resolver,
    connector: harness.connector,
    http: harness.http,
    clock: harness.clock,
  });
  const authorize = vi.fn(async ({ url }: { url: string }) => ({
    kind: "destination-fetch" as const,
    url,
  }));
  const enricher = createDivergenceProbeEnricher({
    transport,
    authorize,
    now: () => harness.clock.now(),
    ...overrides,
  });
  return { harness, authorize, enricher };
}

const CHECK_TOKEN = `resolution:${DIVERGENCE_PROBE_SOURCE_ID}` as const;

function findEvidence(
  result: Awaited<ReturnType<typeof inspectAsync>>,
  type: string,
) {
  return (result.enrichment?.outcomes ?? [])
    .flatMap((outcome) => outcome.evidence)
    .find((item) => item.type === type);
}

function newReasonCodes(
  result: Awaited<ReturnType<typeof inspectAsync>>,
  input: string,
): string[] {
  const before = new Set(inspect(input).reasons.map((reason) => reason.code));
  return result.reasons.map((reason) => reason.code).filter((code) => !before.has(code));
}

describe("L4 controlled-variant divergence probe", () => {
  it("emits one success per variant plus a non-divergent record for identical responses", async () => {
    const url = "https://origin.example/page";
    const same: ResponseStep = {
      url,
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
      body: "<html><body>hello</body></html>",
    };
    const { harness, enricher } = fixtureEnricher([same, same]);

    const result = await inspectAsync(url, { enrichers: [enricher] });
    const outcomes = result.enrichment?.outcomes ?? [];

    expect(outcomes.map((outcome) => outcome.status)).toEqual(["success", "success", "success"]);
    const variantRecords = outcomes
      .flatMap((outcome) => outcome.evidence)
      .filter((item) => item.type === "resolution.variant-response");
    expect(variantRecords).toHaveLength(2);

    const divergence = findEvidence(result, "resolution.divergence");
    expect(divergence?.payload).toMatchObject({ divergent: false, divergentDimensions: [] });
    expect((divergence?.payload as { variants: unknown[] }).variants).toHaveLength(2);

    expect(outcomes.flatMap((outcome) => outcome.findings)).toEqual([]);
    expect(result.checksRun).toContain(CHECK_TOKEN);
    expect(newReasonCodes(result, url)).toEqual([]);
    harness.assertExhausted();
  });

  it("records divergence as evidence only when the alternate UA is cloaked to another domain", async () => {
    const url = "https://origin.example/page";
    const { harness, enricher } = fixtureEnricher([
      {
        url,
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: "<html><body>real</body></html>",
      },
      { url, status: 302, headers: { location: "https://evil.example/landing" } },
    ]);

    const result = await inspectAsync(url, { enrichers: [enricher] });
    const divergence = findEvidence(result, "resolution.divergence");

    expect(divergence?.payload).toMatchObject({ divergent: true });
    const dimensions = (divergence?.payload as { divergentDimensions: string[] }).divergentDimensions;
    expect(dimensions).toContain("location");
    expect(dimensions).toContain("statusClass");

    // Evidence-only: no finding, no new reason codes, confidence untouched.
    expect((result.enrichment?.outcomes ?? []).flatMap((outcome) => outcome.findings)).toEqual([]);
    expect(newReasonCodes(result, url)).toEqual([]);
    harness.assertExhausted();
  });

  it("marks a challenge-gated variant as an explicit resolution-incomplete skip", async () => {
    const url = "https://origin.example/page";
    const { harness, enricher } = fixtureEnricher([
      {
        url,
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: "<html><body>real</body></html>",
      },
      {
        url,
        status: 403,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: '<html><head><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page"></script></head></html>',
      },
    ]);

    const result = await inspectAsync(url, { enrichers: [enricher] });
    const outcomes = result.enrichment?.outcomes ?? [];
    const challenge = outcomes.find(
      (outcome) => outcome.cause?.code === "challenge-gate",
    );

    expect(challenge?.status).toBe("skipped");
    expect(challenge?.cause).toMatchObject({
      code: "challenge-gate",
      retryable: false,
      details: { variant: "alt-user-agent", marker: "cloudflare-challenge" },
    });
    const record = findEvidence(result, "resolution.challenge");
    expect(record?.payload).toMatchObject({
      variant: "alt-user-agent",
      marker: "cloudflare-challenge",
      status: 403,
    });
    expect(result.checksSkipped).toContain(CHECK_TOKEN);
    expect(outcomes.flatMap((outcome) => outcome.findings)).toEqual([]);
    expect(newReasonCodes(result, url)).toEqual([]);
    harness.assertExhausted();
  });

  it("detects a reCAPTCHA gate as a challenge skip", async () => {
    const url = "https://origin.example/page";
    const { harness, enricher } = fixtureEnricher([
      {
        url,
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: '<html><body><div class="g-recaptcha" data-sitekey="x"></div></body></html>',
      },
      {
        url,
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: "<html><body>plain</body></html>",
      },
    ]);

    const result = await inspectAsync(url, { enrichers: [enricher] });
    const challenge = (result.enrichment?.outcomes ?? []).find(
      (outcome) => outcome.cause?.code === "challenge-gate",
    );
    expect(challenge?.cause?.details).toMatchObject({ variant: "baseline", marker: "recaptcha" });
    harness.assertExhausted();
  });

  it("degrades only the refused variant when the second variant is denied", async () => {
    const url = "https://origin.example/page";
    const harness = new TransportFixtureHarness(
      scriptFor([
        {
          url,
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
          body: "<html><body>real</body></html>",
        },
      ]),
    );
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    });
    const authorize = vi.fn(async ({ variant, url: target }: { variant: string; url: string }) =>
      variant === "alt-user-agent" ? null : { kind: "destination-fetch" as const, url: target },
    );
    const enricher = createDivergenceProbeEnricher({
      transport,
      authorize,
      now: () => harness.clock.now(),
    });

    const result = await inspectAsync(url, { enrichers: [enricher] });
    const outcomes = result.enrichment?.outcomes ?? [];

    expect(outcomes[0]?.status).toBe("success");
    const denied = outcomes.find((outcome) => outcome.cause?.code === "authorization-denied");
    expect(denied).toMatchObject({
      status: "skipped",
      cause: { code: "authorization-denied", details: { variant: "alt-user-agent" } },
    });
    expect(authorize).toHaveBeenCalledTimes(2);
    // Only one successful variant, so divergence has nothing to compare.
    expect(findEvidence(result, "resolution.divergence")?.payload).toMatchObject({
      divergent: false,
      divergentDimensions: [],
    });
    harness.assertExhausted();
  });

  it("rejects a non-HTTP initial target before authorization or transport", async () => {
    const harness = new TransportFixtureHarness();
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    });
    const authorize = vi.fn();
    const result = await inspectAsync("mailto:security@example.com", {
      enrichers: [createDivergenceProbeEnricher({
        transport,
        authorize,
        now: () => harness.clock.now(),
      })],
    });

    expect(result.enrichment?.outcomes).toHaveLength(1);
    expect(result.enrichment?.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "invalid-target", retryable: false },
    });
    expect(authorize).not.toHaveBeenCalled();
    expect(harness.http.calls).toEqual([]);
  });
});
