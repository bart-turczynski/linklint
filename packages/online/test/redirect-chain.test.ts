import { describe, expect, it, vi } from "vitest";

import { ENRICHMENT_SCHEMA_VERSION, inspect, inspectAsync } from "linklint";

import {
  DEFAULT_REDIRECT_CHAIN_MAX_HOPS,
  REDIRECT_CHAIN_SOURCE_ID,
  createRedirectChainEnricher,
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
  overrides: Partial<Parameters<typeof createRedirectChainEnricher>[0]> = {},
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
  const enricher = createRedirectChainEnricher({
    transport,
    authorize,
    now: () => harness.clock.now(),
    ...overrides,
  });
  return { harness, authorize, enricher };
}

describe("L1 bounded HTTP redirect expansion", () => {
  it.each([301, 302, 303, 307, 308])(
    "expands status %i with a relative Location and fresh exact-URL authorization",
    async (status) => {
      const start = "https://origin.example/start";
      const next = "https://origin.example/landing?from=redirect";
      const { harness, authorize, enricher } = fixtureEnricher([
        { url: start, status, headers: { location: "/landing?from=redirect" } },
        { url: next, status: 200, headers: { "content-type": "text/plain" }, body: "done" },
      ]);

      const result = await inspectAsync(start, { enrichers: [enricher] });

      expect(result.enrichment?.schemaVersion).toBe(ENRICHMENT_SCHEMA_VERSION);
      expect(result.enrichment?.outcomes.map((outcome) => outcome.subject.value)).toEqual([
        start,
        next,
      ]);
      expect(result.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
        "success",
        "success",
      ]);
      expect(result.enrichment?.outcomes[0]?.evidence[0]?.payload).toMatchObject({
        hop: 1,
        responseStatus: status,
        transition: { kind: "http-redirect", targetUrl: next, delayMs: null },
      });
      expect(authorize.mock.calls.map(([request]) => request)).toEqual([
        expect.objectContaining({ url: start, hop: 1, reason: "initial" }),
        expect.objectContaining({
          url: next,
          hop: 2,
          reason: "http-redirect",
          fromUrl: start,
        }),
      ]);
      harness.assertExhausted();
    },
  );

  it("keeps ordered evidence for every hop but scores only the worst hop without duplicate codes", async () => {
    const start = "https://origin.example/start";
    const risky = "https://paypa1.com/secure/login";
    const final = "https://example.com/done";
    const { harness, enricher } = fixtureEnricher([
      { url: start, status: 302, headers: { location: risky } },
      { url: risky, status: 307, headers: { location: final } },
      { url: final, status: 200, headers: { "content-type": "text/plain" }, body: "done" },
    ]);

    const result = await inspectAsync(start, { enrichers: [enricher] });
    const outcomes = result.enrichment?.outcomes ?? [];

    expect(outcomes.map((outcome) => outcome.subject.value)).toEqual([start, risky, final]);
    expect(outcomes.map((outcome) => outcome.observedAt)).toEqual([
      START_TIME,
      START_TIME,
      START_TIME,
    ]);
    expect(outcomes[0]?.findings).toEqual([]);
    expect(outcomes[1]?.findings.map((finding) => finding.code)).toEqual(
      [...new Set(inspect(risky).reasons.map((reason) => reason.code))],
    );
    expect(outcomes[2]?.findings).toEqual([]);
    const projectedCodes = outcomes.flatMap((outcome) => outcome.findings.map((item) => item.code));
    expect(new Set(projectedCodes).size).toBe(projectedCodes.length);
    expect(result.reasons.map((reason) => reason.code)).toContain("brand_homoglyph");
    expect(result.checksRun).toContain(`resolution:${REDIRECT_CHAIN_SOURCE_ID}`);
    harness.assertExhausted();
  });

  it("treats an opaque shortener as an ordinary L0 redirect", async () => {
    const start = "https://bit.ly/opaque";
    const target = "https://example.com/landing";
    const { harness, enricher } = fixtureEnricher([
      { url: start, status: 302, headers: { location: target } },
      { url: target, status: 204 },
    ]);

    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes.map((outcome) => outcome.subject.value)).toEqual([
      start,
      target,
    ]);
    harness.assertExhausted();
  });

  it("uses HEAD unchanged and does not inspect an unavailable response body for meta refresh", async () => {
    const start = "https://origin.example/start";
    const { harness, enricher } = fixtureEnricher(
      [{
        url: start,
        method: "HEAD",
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: '<meta http-equiv="refresh" content="0; url=/not-followed">',
      }],
      { method: "HEAD" },
    );
    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes).toHaveLength(1);
    expect(harness.http.calls[0]?.method).toBe("HEAD");
    harness.assertExhausted();
  });
});

describe("L1 bounded declarative refresh expansion", () => {
  it("expands an HTTP Refresh header under the shared HTML policy", async () => {
    const start = "https://origin.example/start";
    const next = "https://origin.example/header-target";
    const { harness, authorize, enricher } = fixtureEnricher([
      {
        url: start,
        status: 200,
        headers: {
          refresh: "1.5; url=/header-target",
          "content-type": "text/html; charset=utf-8",
        },
        body: "<html></html>",
      },
      { url: next, status: 200, headers: { "content-type": "text/plain" } },
    ]);

    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes[0]?.evidence[0]?.payload).toMatchObject({
      transition: { kind: "http-refresh", targetUrl: next, delayMs: 1500 },
    });
    expect(authorize.mock.calls[1]?.[0]).toMatchObject({ reason: "http-refresh", url: next });
    harness.assertExhausted();
  });

  it("expands the first real meta refresh while ignoring script text and decoding entities", async () => {
    const start = "https://origin.example/start";
    const next = "https://origin.example/meta-target?a=1&b=2";
    const html = [
      "<script>const fake = '<meta http-equiv=refresh content=\"0;url=/wrong\">';</script>",
      '<meta content="0; url=/meta-target?a=1&amp;b=2" http-equiv="Refresh">',
      "<script>location='/also-not-followed'</script>",
    ].join("");
    const { harness, enricher } = fixtureEnricher([
      {
        url: start,
        status: 200,
        headers: { "content-type": "text/html; charset=windows-1252" },
        body: html,
      },
      { url: next, status: 200, headers: { "content-type": "text/plain" } },
    ]);

    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes[0]?.evidence[0]?.payload).toMatchObject({
      transition: { kind: "html-meta-refresh", targetUrl: next, delayMs: 0 },
    });
    expect(result.enrichment?.outcomes).toHaveLength(2);
    harness.assertExhausted();
  });

  it.each([
    {
      name: "delay",
      headers: { refresh: "6; url=/next", "content-type": "text/html; charset=utf-8" },
      body: "",
      options: { maxRefreshDelayMs: 5_000 },
      code: "refresh-delay-exceeded",
      status: "skipped",
    },
    {
      name: "MIME",
      headers: { refresh: "0; url=/next", "content-type": "text/plain; charset=utf-8" },
      body: "",
      options: {},
      code: "refresh-mime-unsupported",
      status: "skipped",
    },
    {
      name: "charset",
      headers: { refresh: "0; url=/next", "content-type": "text/html; charset=utf-16" },
      body: "",
      options: {},
      code: "refresh-charset-unsupported",
      status: "failure",
    },
    {
      name: "byte",
      headers: { "content-type": "text/html; charset=utf-8" },
      body: '<meta http-equiv="refresh" content="0;url=/next">',
      options: { maxRefreshBytes: 8 },
      code: "refresh-body-too-large",
      status: "failure",
    },
    {
      name: "grammar",
      headers: { refresh: "0; /missing-url-marker", "content-type": "text/html" },
      body: "",
      options: {},
      code: "invalid-refresh",
      status: "failure",
    },
  ])("stops explicitly when the shared $name policy rejects refresh", async (testCase) => {
    const start = "https://origin.example/start";
    const { harness, enricher } = fixtureEnricher(
      [{
        url: start,
        status: 200,
        headers: testCase.headers,
        body: testCase.body,
      }],
      testCase.options,
    );
    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
      "success",
      testCase.status,
    ]);
    expect(result.enrichment?.outcomes[1]?.cause?.code).toBe(testCase.code);
    harness.assertExhausted();
  });

  it("does not execute or infer JavaScript navigation", async () => {
    const start = "https://origin.example/start";
    const { harness, authorize, enricher } = fixtureEnricher([{
      url: start,
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
      body: "<script>window.location='https://evil.example/'</script>",
    }]);
    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes).toHaveLength(1);
    expect(authorize).toHaveBeenCalledTimes(1);
    harness.assertExhausted();
  });
});

describe("L1 explicit stop and degradation outcomes", () => {
  it.each([
    {
      name: "loop",
      headers: { location: "/start" },
      options: {},
      code: "redirect-loop",
    },
    {
      name: "hop cap",
      headers: { location: "/next" },
      options: { maxHops: 1 },
      code: "hop-limit",
    },
    {
      name: "invalid target",
      headers: { location: "mailto:security@example.com" },
      options: {},
      code: "invalid-target",
    },
  ])("records an explicit $name stop", async (testCase) => {
    const start = "https://origin.example/start";
    const { harness, enricher } = fixtureEnricher(
      [{ url: start, status: 302, headers: testCase.headers }],
      testCase.options,
    );
    const result = await inspectAsync(start, { enrichers: [enricher] });
    expect(result.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
      "success",
      "failure",
    ]);
    expect(result.enrichment?.outcomes[1]?.cause?.code).toBe(testCase.code);
    expect(result.checksRun).toContain(`resolution:${REDIRECT_CHAIN_SOURCE_ID}`);
    expect(result.checksSkipped).toContain(`resolution:${REDIRECT_CHAIN_SOURCE_ID}`);
    harness.assertExhausted();
  });

  it("does not let invalid max-hop configuration remove the default bound", () => {
    const start = "https://origin.example/start";
    const { enricher } = fixtureEnricher([{ url: start, status: 200 }], { maxHops: 0 });
    expect(enricher).toBeDefined();
    expect(DEFAULT_REDIRECT_CHAIN_MAX_HOPS).toBeGreaterThan(0);
  });

  it("stops before transport when the caller denies exact-URL authorization", async () => {
    const harness = new TransportFixtureHarness();
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    });
    const result = await inspectAsync("https://origin.example/start", {
      enrichers: [createRedirectChainEnricher({
        transport,
        authorize: () => null,
        now: () => harness.clock.now(),
      })],
    });
    expect(result.enrichment?.outcomes[0]).toMatchObject({
      status: "skipped",
      cause: { code: "authorization-denied", retryable: false },
    });
    expect(harness.resolver.calls).toEqual([]);
    expect(harness.connector.calls).toEqual([]);
    expect(harness.http.calls).toEqual([]);
  });

  it("preserves L0 prohibited-address evidence as a blocked-policy skip", async () => {
    const start = "https://origin.example/start";
    const harness = new TransportFixtureHarness({
      startTime: START_TIME,
      resolver: [{
        hostname: "origin.example",
        outcome: {
          value: [{ address: "169.254.169.254", family: 4, ttlSeconds: 1 }],
        },
      }],
    });
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    });
    const result = await inspectAsync(start, {
      enrichers: [createRedirectChainEnricher({
        transport,
        authorize: ({ url }) => ({ kind: "destination-fetch", url }),
        now: () => harness.clock.now(),
      })],
    });
    expect(result.enrichment?.outcomes[0]).toMatchObject({
      status: "skipped",
      subject: { kind: "url", value: start },
      cause: {
        code: "prohibited-address",
        retryable: false,
        details: { category: "ip_cloud_metadata" },
      },
      evidence: expect.arrayContaining([
        expect.objectContaining({ type: "transport.attempt" }),
      ]),
    });
    harness.assertExhausted();
  });

  it("preserves an attempted transport failure as explicit incomplete coverage", async () => {
    const start = "https://origin.example/start";
    const harness = new TransportFixtureHarness({
      startTime: START_TIME,
      resolver: [{ hostname: "origin.example", outcome: { value: [] } }],
    });
    const transport = createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    });
    const result = await inspectAsync(start, {
      enrichers: [createRedirectChainEnricher({
        transport,
        authorize: ({ url }) => ({ kind: "destination-fetch", url }),
        now: () => harness.clock.now(),
      })],
    });
    expect(result.enrichment?.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "dns-not-found", retryable: false },
    });
    expect(result.checksSkipped).toContain(`resolution:${REDIRECT_CHAIN_SOURCE_ID}`);
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
      enrichers: [createRedirectChainEnricher({
        transport,
        authorize,
        now: () => harness.clock.now(),
      })],
    });
    expect(result.enrichment?.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "invalid-target", retryable: false },
    });
    expect(authorize).not.toHaveBeenCalled();
  });
});
