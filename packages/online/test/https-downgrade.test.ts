import { describe, expect, it, vi } from "vitest";

import { inspectAsync } from "linklint";

import { createRedirectChainEnricher } from "../src/resolution/index.js";
import { createSafeTransport } from "../src/transport/index.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../src/testing/index.js";

/**
 * An HTTPS -> HTTP downgrade mid-chain (`LINK-emlbzwct`).
 *
 * The fact was already fully DERIVABLE from the `resolution.chain-hop` payloads
 * — each carries `transport.protocol` for the hop it fetched and the ordered
 * `transition.targetUrl` it was sent to — but nothing NAMED it, so a consumer
 * had to reconstruct the scheme sequence itself to learn that a chain left TLS.
 * These tests pin the derivability and the silence BEFORE the code exists, then
 * flip only the silence assertions when it does.
 *
 * Refusing the downgrade was decided against 2-1: refusal buys no
 * confidentiality (L0 sends no body, no cookies, no credentials and strips the
 * caller's `Referer`) while costing detection, because a refused hop is never
 * fetched and `worstHop`, `correlateOpenRedirect` and `mimeEvidenceFor` all read
 * fetched hops only. The chain is observed and reported, never stopped.
 */

const PUBLIC_ADDRESS = "93.184.216.34";
const START_TIME = "2026-07-17T12:00:00.000Z";
const DOWNGRADE_CODE = "https_downgrade_observed";

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

type AsyncResult = Awaited<ReturnType<typeof inspectAsync>>;

function findingCodes(result: AsyncResult): string[] {
  return (result.enrichment?.outcomes ?? []).flatMap((outcome) =>
    outcome.findings.map((finding) => finding.code),
  );
}

function reasonCodes(result: AsyncResult): string[] {
  return result.reasons.map((reason) => reason.code);
}

function chainHopPayloads(result: AsyncResult): Record<string, unknown>[] {
  return (result.enrichment?.outcomes ?? []).flatMap((outcome) =>
    outcome.evidence
      .filter((item) => item.type === "resolution.chain-hop")
      .map((item) => item.payload as Record<string, unknown>),
  );
}

/** The three transition kinds, each carrying the same https -> http downgrade. */
const DOWNGRADE_CHAINS = [
  {
    kind: "http-redirect",
    steps: [
      {
        url: "https://origin.example/start",
        status: 302,
        headers: { location: "http://origin.example/landing" },
      },
      {
        url: "http://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ],
  },
  {
    kind: "http-refresh",
    steps: [
      {
        url: "https://origin.example/start",
        status: 200,
        headers: {
          refresh: "0; url=http://origin.example/landing",
          "content-type": "text/html; charset=utf-8",
        },
        body: "<html></html>",
      },
      {
        url: "http://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ],
  },
  {
    kind: "html-meta-refresh",
    steps: [
      {
        url: "https://origin.example/start",
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: '<meta http-equiv="refresh" content="0; url=http://origin.example/landing">',
      },
      {
        url: "http://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ],
  },
] as const;

describe("an https -> http downgrade is derivable from the shipped chain evidence", () => {
  // The premise of the whole unit: the scheme sequence is already IN the
  // artifact. If these assertions stop holding, naming the fact is no longer a
  // projection of existing evidence but a new claim, and the design changes.
  it.each(DOWNGRADE_CHAINS)("$kind carries both schemes in the hop payloads", async (chain) => {
    const { harness, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });
    const payloads = chainHopPayloads(result);

    expect(payloads).toHaveLength(2);
    expect(payloads[0]).toMatchObject({
      hop: 1,
      requestUrl: "https://origin.example/start",
      transport: { protocol: "https:" },
      transition: { kind: chain.kind, targetUrl: "http://origin.example/landing" },
    });
    expect(payloads[1]).toMatchObject({
      hop: 2,
      requestUrl: "http://origin.example/landing",
      transport: { protocol: "http:" },
      transition: null,
    });
    harness.assertExhausted();
  });
});

describe("the downgrade is not yet NAMED by any finding", () => {
  // PIN, THEN MUTATE. These four assertions are the silence this unit closes;
  // the commit that adds the reason code flips them to `toContain`.
  it.each(DOWNGRADE_CHAINS)("$kind reports no downgrade finding", async (chain) => {
    const { harness, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });

    expect(findingCodes(result)).not.toContain(DOWNGRADE_CODE);
    expect(reasonCodes(result)).not.toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });

  it("an https -> http -> https bounce reports no downgrade finding", async () => {
    const steps = [
      {
        url: "https://origin.example/start",
        status: 302,
        headers: { location: "http://origin.example/middle" },
      },
      {
        url: "http://origin.example/middle",
        status: 302,
        headers: { location: "https://origin.example/landing" },
      },
      {
        url: "https://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ];
    const { harness, enricher } = fixtureEnricher(steps);
    const result = await inspectAsync(steps[0]!.url, { enrichers: [enricher] });

    expect(findingCodes(result)).not.toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });
});

describe("cases that must NEVER be read as a downgrade", () => {
  // These stay `not.toContain` in every later commit. A downgrade is a
  // TRANSITION from https: to http:, never a property of a single hop's scheme
  // — `canonicalHttpUrl` accepts an `http://` input at hop 1 and a plaintext
  // origin is an ordinary, fully supported chain start.
  it("an http -> https UPGRADE is not a downgrade", async () => {
    const steps = [
      {
        url: "http://origin.example/start",
        status: 301,
        headers: { location: "https://origin.example/landing" },
      },
      {
        url: "https://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ];
    const { harness, enricher } = fixtureEnricher(steps);
    const result = await inspectAsync(steps[0]!.url, { enrichers: [enricher] });

    expect(chainHopPayloads(result)[0]).toMatchObject({ transport: { protocol: "http:" } });
    expect(findingCodes(result)).not.toContain(DOWNGRADE_CODE);
    expect(reasonCodes(result)).not.toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });

  it("a plaintext ORIGIN that stays plaintext is not a downgrade", async () => {
    const steps = [
      {
        url: "http://origin.example/start",
        status: 302,
        headers: { location: "http://origin.example/landing" },
      },
      {
        url: "http://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ];
    const { harness, enricher } = fixtureEnricher(steps);
    const result = await inspectAsync(steps[0]!.url, { enrichers: [enricher] });

    expect(chainHopPayloads(result).map((payload) => payload["transport"])).toEqual([
      expect.objectContaining({ protocol: "http:" }),
      expect.objectContaining({ protocol: "http:" }),
    ]);
    expect(findingCodes(result)).not.toContain(DOWNGRADE_CODE);
    expect(reasonCodes(result)).not.toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });

  it("an https -> https hop is not a downgrade", async () => {
    const steps = [
      {
        url: "https://origin.example/start",
        status: 302,
        headers: { location: "https://origin.example/landing" },
      },
      {
        url: "https://origin.example/landing",
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "done",
      },
    ];
    const { harness, enricher } = fixtureEnricher(steps);
    const result = await inspectAsync(steps[0]!.url, { enrichers: [enricher] });

    expect(findingCodes(result)).not.toContain(DOWNGRADE_CODE);
    expect(reasonCodes(result)).not.toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });
});
