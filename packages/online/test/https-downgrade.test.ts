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
 * These tests pinned the derivability and the silence BEFORE the code existed;
 * registering the code is what reddened the silence half, which is the proof
 * that those assertions bite.
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

describe("the downgrade is NAMED, for all three transition kinds", () => {
  // These four were `not.toContain` in the commit that pinned the silence, and
  // registering the code is what reddened them — the mutation proof for the pin.
  it.each(DOWNGRADE_CHAINS)("$kind raises the downgrade finding", async (chain) => {
    const { harness, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });

    expect(findingCodes(result)).toContain(DOWNGRADE_CODE);
    expect(reasonCodes(result)).toContain(DOWNGRADE_CODE);
    harness.assertExhausted();
  });

  it("attaches the finding and its evidence to the hop that ISSUED the downgrade", async () => {
    const chain = DOWNGRADE_CHAINS[0];
    const { harness, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });
    const outcomes = result.enrichment?.outcomes ?? [];

    expect(outcomes[0]?.findings.map((finding) => finding.code)).toContain(DOWNGRADE_CODE);
    expect(outcomes[1]?.findings.map((finding) => finding.code)).not.toContain(DOWNGRADE_CODE);

    const evidence = outcomes[0]?.evidence.find(
      (item) => item.type === "resolution.https-downgrade",
    );
    expect(evidence?.subject).toEqual({ kind: "url", value: "https://origin.example/start" });
    expect(evidence?.payload).toMatchObject({
      hop: 1,
      targetHop: 2,
      transitionKind: "http-redirect",
      fromUrl: "https://origin.example/start",
      fromScheme: "https:",
      toUrl: "http://origin.example/landing",
      toScheme: "http:",
      transportProtocol: "https:",
    });
    harness.assertExhausted();
  });

  it("carries the transition kind of each mechanism into the evidence", async () => {
    for (const chain of DOWNGRADE_CHAINS) {
      const { harness, enricher } = fixtureEnricher(chain.steps);
      const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });
      const evidence = (result.enrichment?.outcomes ?? [])
        .flatMap((outcome) => outcome.evidence)
        .find((item) => item.type === "resolution.https-downgrade");
      expect(evidence?.payload).toMatchObject({ transitionKind: chain.kind });
      harness.assertExhausted();
    }
  });

  it("is informational: weight 0, resolution layer, score and confidence untouched", async () => {
    const chain = DOWNGRADE_CHAINS[0];
    const { harness, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });
    const reason = result.reasons.find((item) => item.code === DOWNGRADE_CODE);

    // A downgrade is not deceptive: the chain does not misrepresent itself and
    // no two readers disagree about what it says. It annotates, it never scores.
    expect(reason?.weight).toBe(0);
    expect(reason?.layer).toBe("resolution");
    expect(result.score).toBe(0);
    expect(result.severity).toBe("info");
    expect(result.confidence).toBe(1);
    harness.assertExhausted();
  });

  it("never stops the chain — every hop after the downgrade is still fetched", async () => {
    const chain = DOWNGRADE_CHAINS[0];
    const { harness, authorize, enricher } = fixtureEnricher(chain.steps);
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });

    // Observe and report. Refusal would buy no confidentiality and would cost
    // the plaintext hop's own evidence, which only a fetch can produce.
    expect(authorize).toHaveBeenCalledTimes(2);
    expect(result.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
      "success",
      "success",
    ]);
    expect(result.enrichment?.outcomes.map((outcome) => outcome.subject.value)).toEqual([
      "https://origin.example/start",
      "http://origin.example/landing",
    ]);
    harness.assertExhausted();
  });

  it("reports the bounce at the hop where it happened and keeps the rest of the chain", async () => {
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
    const outcomes = result.enrichment?.outcomes ?? [];

    // Hop 1 downgraded; hop 2's re-upgrade is not a second downgrade and does
    // not retract the first; hop 3 is terminal.
    expect(outcomes.map((outcome) => outcome.findings.map((finding) => finding.code))).toEqual([
      [DOWNGRADE_CODE],
      [],
      [],
    ]);
    expect(outcomes.map((outcome) => outcome.subject.value)).toEqual(steps.map((step) => step.url));
    harness.assertExhausted();
  });

  it("reports a downgrade the chain was directed into even when it is never fetched", async () => {
    // Keyed on the TRANSITION, not on the target hop's fetch: the redirect that
    // named the plaintext target was itself fetched and proves the downgrade,
    // and a refused or capped hop must not erase it.
    const chain = DOWNGRADE_CHAINS[0];
    const { harness, enricher } = fixtureEnricher([chain.steps[0]], { maxHops: 1 });
    const result = await inspectAsync(chain.steps[0].url, { enrichers: [enricher] });

    expect(findingCodes(result)).toContain(DOWNGRADE_CODE);
    expect(result.enrichment?.outcomes.at(-1)?.cause?.code).toBe("hop-limit");
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
