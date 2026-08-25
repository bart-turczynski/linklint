import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { inspectAsync } from "linklint";
import type { EnrichmentOutcome } from "linklint";

import { createRedirectChainEnricher } from "../src/resolution/index.js";
import { createTlsCertificateEnricher } from "../src/reputation/index.js";
import { createSafeTlsInspector, createSafeTransport } from "../src/transport/index.js";
import type { SafeTlsInspector } from "../src/transport/index.js";
import { TransportFixtureHarness } from "../src/testing/index.js";
import type { FixtureConnection, TransportFixtureScript } from "../src/testing/index.js";
import { handshake } from "./fixtures/tls-certificates.js";

/**
 * The input-origin-only TLS semantics, pinned against the documents that
 * publish them (LINK-pyvuxaac, recording the LINK-wwnrkjnm decision).
 *
 * WHY A PIN AT ALL. `LINK-wwnrkjnm` declined wiring the TLS enricher to the
 * redirect chain through `dependsOn` partly because the worked `https://iana.org/`
 * run in `docs/online-composition-root.md` would have INVERTED — the chain is
 * `skipped` with `authorization-denied` there, and `runIsAvailable` would then
 * have turned the neighbouring `success` TLS outcome into
 * `prerequisite-unavailable`. That example was prose, so the inversion would
 * have shipped as silent doc drift with the suite green. Unlike a record whose
 * content is a set of absences, these two examples ARE derivable from a real
 * run, so there is runtime behavior available to contradict them — and this
 * file derives both from fixture-driven `inspectAsync` runs and matches the
 * derivation against the published blocks. Wiring `dependsOn` (or moving the
 * skip guard behind the inspector call) turns this file red.
 *
 * HARD-WRAP TRAP. Both documents wrap at ~80 columns, and the printed blocks
 * are column-padded, so a raw substring match finds NOTHING while still reading
 * as a passing assertion. Every assertion below runs against `flatten(...)`,
 * which strips leading `>` / `*` markers and collapses whitespace. The
 * "flattening bites" block at the bottom shows the swap: the same needles
 * against the RAW document are absent, which is what makes the matches above
 * non-vacuous.
 *
 * Fixture-driven, fixed clock, zero network.
 */

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const compositionRootDoc = readFileSync(
  join(REPO_ROOT, "docs", "online-composition-root.md"),
  "utf8",
);
const sourceContractDoc = readFileSync(
  join(REPO_ROOT, "docs", "online-source-contract.md"),
  "utf8",
);

/** Strip leading `>` / `*` markers per line, then collapse every run of whitespace. */
function flatten(text: string): string {
  return text.replace(/^\s*(?:>|\*)\s?/gm, "").replace(/\s+/g, " ");
}

function slice(doc: string, from: string, to: string): string {
  const start = doc.indexOf(from);
  const end = doc.indexOf(to, start + from.length);
  expect(start, `missing section start: ${from}`).toBeGreaterThan(-1);
  expect(end, `missing section end: ${to}`).toBeGreaterThan(start);
  return doc.slice(start, end);
}

const PUBLISHED_HTTPS_BLOCK = slice(
  compositionRootDoc,
  "### `enrichment.outcomes[]`",
  "### Chain success is not TLS evidence",
);
const PUBLISHED_HTTP_BLOCK = slice(
  compositionRootDoc,
  "### Chain success is not TLS evidence",
  "## Sources this root deliberately omits",
);
const SEMANTICS_SECTION = slice(
  sourceContractDoc,
  "### The live TLS source's subject is the input origin",
  "## The shared contract-test kit",
);

// ── Fixture transport (mirrors resolution-acceptance.test.ts) ────────────────
const PUBLIC_A = "93.184.216.34";
const START_TIME = "2026-07-17T12:00:00.000Z";

interface Step {
  readonly url: string;
  readonly status: number;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

function connection(id: string, url: string): FixtureConnection {
  const parsed = new URL(url);
  const port = parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
  return {
    id,
    protocol: parsed.protocol as "http:" | "https:",
    remoteAddress: PUBLIC_A,
    remotePort: port,
    ...(parsed.protocol === "https:"
      ? { tls: { authorized: true, serverName: parsed.hostname, peerDnsNames: [parsed.hostname] } }
      : {}),
  };
}

function scriptFor(steps: readonly Step[]): TransportFixtureScript {
  return {
    startTime: START_TIME,
    resolver: steps.map((step) => ({
      hostname: new URL(step.url).hostname,
      outcome: { value: [{ address: PUBLIC_A, family: 4 as const, ttlSeconds: 60 }] },
    })),
    connector: steps.map((step, index) => {
      const parsed = new URL(step.url);
      const port =
        parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
      return {
        expect: {
          protocol: parsed.protocol as "http:" | "https:",
          hostname: parsed.hostname,
          address: PUBLIC_A,
          port,
          ...(parsed.protocol === "https:" ? { serverName: parsed.hostname } : {}),
        },
        outcome: { value: connection(`c${index + 1}`, step.url) },
      };
    }),
    http: steps.map((step, index) => ({
      expect: { connectionId: `c${index + 1}`, url: step.url, method: "GET" },
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

function transportFor(steps: readonly Step[]): {
  transport: ReturnType<typeof createSafeTransport>;
  now: () => Date;
} {
  const harness = new TransportFixtureHarness(scriptFor(steps));
  return {
    transport: createSafeTransport({
      resolver: harness.resolver,
      connector: harness.connector,
      http: harness.http,
      clock: harness.clock,
    }),
    now: () => harness.clock.now(),
  };
}

/** The one-line form the composition-root doc prints per outcome. */
function printed(outcome: EnrichmentOutcome): string {
  const subject = `${outcome.subject.kind}=${outcome.subject.value}`;
  const cause = outcome.cause === undefined ? "" : ` cause=${outcome.cause.code}`;
  return `${outcome.layer}:${outcome.sourceId} ${outcome.status} ${subject}${cause}`;
}

function tlsEnricher(inspector: SafeTlsInspector, now: () => Date) {
  return createTlsCertificateEnricher({
    terms: { commercialMode: "commercial" },
    inspector,
    now,
  });
}

const ALLOW_ALL = async ({ url }: { url: string }) =>
  ({ kind: "destination-fetch" as const, url }) satisfies { kind: "destination-fetch"; url: string };

describe("the published http:// run: chain success beside TLS skipped (LINK-pyvuxaac)", () => {
  it("is what a real fixture-driven run prints, and costs zero inspector calls", async () => {
    const { transport, now } = transportFor([
      { url: "http://iana.org/", status: 301, headers: { location: "https://www.iana.org/" } },
      { url: "https://www.iana.org/", status: 200, body: "<html></html>" },
    ]);
    let inspected = 0;
    const inspector: SafeTlsInspector = {
      inspect: async () => {
        inspected += 1;
        throw new Error("the input-origin guard must run ahead of any inspector call");
      },
    };

    const result = await inspectAsync("http://iana.org/", {
      enrichers: [
        createRedirectChainEnricher({ transport, authorize: ALLOW_ALL, now }),
        tlsEnricher(inspector, now),
      ],
    });
    const lines = (result.enrichment?.outcomes ?? []).map(printed);

    // The guard precedes any DNS or socket work: the inspector is never reached.
    expect(inspected).toBe(0);

    // The chain SUCCEEDED and reached a live HTTPS endpoint...
    expect(lines).toContain("resolution:redirect-chain.http success url=http://iana.org/");
    expect(lines).toContain("resolution:redirect-chain.http success url=https://www.iana.org/");
    // ...and TLS is still skipped on the http:// input, with no evidence for the
    // endpoint the chain resolved to.
    expect(lines).toContain(
      "reputation:tls.live-endpoint skipped url=http://iana.org/ cause=tls-not-https-endpoint",
    );
    expect(
      (result.enrichment?.outcomes ?? []).flatMap((outcome) => outcome.evidence),
      "no artifact may describe the resolved endpoint's certificate",
    ).not.toContainEqual(expect.objectContaining({ type: "tls.certificate" }));

    const flat = flatten(PUBLISHED_HTTP_BLOCK);
    for (const line of lines) expect(flat, `doc block is missing: ${line}`).toContain(line);
    expect(flat).toContain("checksRun: lexical, resolution:redirect-chain.http");
    expect(flat).toContain("checksSkipped: reputation:tls.live-endpoint");
    expect(result.checksRun).toEqual(["lexical", "resolution:redirect-chain.http"]);
    expect(result.checksSkipped).toEqual(["reputation:tls.live-endpoint"]);
  });
});

describe("the published https://iana.org/ run does not invert (LINK-pyvuxaac)", () => {
  it("keeps TLS success beside a chain refused for authorization", async () => {
    const { transport, now } = transportFor([]);
    const tlsHarness = new TransportFixtureHarness({
      startTime: START_TIME,
      resolver: [
        {
          hostname: "iana.org",
          outcome: { value: [{ address: PUBLIC_A, family: 4 as const, ttlSeconds: 60 }] },
        },
      ],
      tlsObserver: [
        {
          expect: { hostname: "iana.org", address: PUBLIC_A, port: 443, serverName: "iana.org" },
          outcome: { value: handshake("valid") },
        },
      ],
    });
    const inspector = createSafeTlsInspector({
      resolver: tlsHarness.resolver,
      observer: tlsHarness.tlsObserver,
      clock: tlsHarness.clock,
    });

    const result = await inspectAsync("https://iana.org/", {
      enrichers: [
        createRedirectChainEnricher({ transport, authorize: async () => null, now }),
        tlsEnricher(inspector, () => tlsHarness.clock.now()),
      ],
    });
    const lines = (result.enrichment?.outcomes ?? []).map(printed);

    // This pair is the one the declined `dependsOn` wiring would have flipped:
    // a degraded chain outcome would have suppressed the TLS source into
    // `prerequisite-unavailable`.
    expect(lines).toContain(
      "resolution:redirect-chain.http skipped url=https://iana.org/ cause=authorization-denied",
    );
    expect(lines).toContain("reputation:tls.live-endpoint success host=iana.org");
    expect(lines.join("\n")).not.toContain("prerequisite-unavailable");

    const flat = flatten(PUBLISHED_HTTPS_BLOCK);
    for (const line of lines) expect(flat, `doc block is missing: ${line}`).toContain(line);
  });

  it("stays independent of the chain because the source declares no dependsOn", () => {
    const enricher = tlsEnricher({ inspect: async () => ({}) as never }, () => new Date(0));
    expect(enricher.dependsOn).toBeUndefined();
  });
});

describe("docs/online-source-contract.md states the semantics (LINK-pyvuxaac)", () => {
  const flat = flatten(SEMANTICS_SECTION);

  it("the section exists and the slice is not empty (anti-vacuity)", () => {
    expect(flat.length).toBeGreaterThan(1500);
    expect(flat).toContain("createTlsCertificateEnricher");
  });

  it("names the input origin as the subject and the pre-connection skip", () => {
    expect(flat).toContain("reads `parsed.scheme` and `parsed.effectiveHost` off the inspected");
    expect(flat).toContain("`cause.code: \"tls-not-https-endpoint\"`");
    expect(flat).toContain("so such an input costs no DNS query and opens no socket");
  });

  it("states that chain success does not imply TLS metadata for the resolved endpoint", () => {
    expect(flat).toContain(
      "successful redirect resolution does not imply TLS metadata for the resolved endpoint",
    );
    expect(flat).toContain("a consumer must not read one as the other");
  });

  it("calls the gap a gap", () => {
    expect(flat).toContain("evidence gap this leaves is real and unclosed");
    expect(flat).toContain(
      "For an `http://` input, the certificate a user would actually meet goes uninspected",
    );
  });

  it("gives the two reasons dependsOn is the wrong fix", () => {
    expect(flat).toContain(
      "would invert to `prerequisite-unavailable`: HTTPS inputs that carry certificate evidence today would stop carrying it",
    );
    // NOTE the marker strip: `**F6**,` lands at the start of a wrapped line, so
    // flattening removes one leading `*`. Match around it rather than through it.
    expect(flat).toContain(
      "`SafeTlsInspector.inspect` takes `{ url, signal }` with no `authorize` callback",
    );
    expect(flat).toContain("register entry");
    expect(flat).toContain("F6**, which holds that construction is not consent to connect");
  });

  it("names the successor shape and the standing constraint", () => {
    expect(flat).toContain("`LINK-boqmfrcn`");
    expect(flat).toContain(
      "the redirect chain already completes an authorized TLS handshake on every HTTPS hop it fetches",
    );
    expect(flat).toContain(
      "Until an authorization seam exists (`LINK-sndjnmig`), no code path may hand a redirect-discovered URL to `SafeTlsInspector.inspect`",
    );
  });
});

describe("the flattening bites — the same needles are absent from the raw documents", () => {
  // Swap `flatten(...)` for the raw slice in any assertion above and it goes
  // red. These four are the proof, one per needle shape: a hard-wrapped
  // sentence, a wrapped bullet, a column-padded printed line, and a padded
  // coverage-token line.
  it("hard-wrapped prose is not found raw", () => {
    expect(SEMANTICS_SECTION).not.toContain(
      "successful redirect resolution does not imply TLS metadata for the resolved endpoint",
    );
    expect(SEMANTICS_SECTION).not.toContain(
      "Until an authorization seam exists (`LINK-sndjnmig`), no code path may hand a redirect-discovered URL to `SafeTlsInspector.inspect`",
    );
  });

  it("column-padded printed lines are not found raw", () => {
    expect(PUBLISHED_HTTP_BLOCK).not.toContain(
      "reputation:tls.live-endpoint skipped url=http://iana.org/ cause=tls-not-https-endpoint",
    );
    expect(PUBLISHED_HTTPS_BLOCK).not.toContain(
      "resolution:redirect-chain.http skipped url=https://iana.org/ cause=authorization-denied",
    );
    expect(PUBLISHED_HTTP_BLOCK).not.toContain("checksRun: lexical, resolution:redirect-chain.http");
  });
});
