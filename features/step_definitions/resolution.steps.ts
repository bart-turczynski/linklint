import assert from "node:assert/strict";
import { DataTable, Given, Then, When } from "@cucumber/cucumber";

import { inspect, inspectAsync } from "../../packages/core/src/index.js";
import type { EnrichmentOutcome } from "../../packages/core/src/index.js";
import {
  createDivergenceProbeEnricher,
  createEmbeddedWrapperEnricher,
  createRedirectChainEnricher,
} from "../../packages/online/src/resolution/index.js";
import type { LinklintWorld } from "../support/world.js";
import {
  allowAll,
  buildFixtureTransport,
  frozenNow,
  microsoftSafeLink,
  type ResponseStep,
} from "../support/resolution.js";

// --- Given: script the deterministic fixture transport -----------------------

interface HopRow {
  readonly url: string;
  readonly status?: string;
  readonly location?: string;
  readonly contentType?: string;
  readonly nosniff?: string;
  readonly refresh?: string;
  readonly body?: string;
  readonly method?: string;
}

function toResponseStep(row: HopRow): ResponseStep {
  const headers: Record<string, string> = {};
  if (row.location) headers.location = row.location;
  if (row.contentType) headers["content-type"] = row.contentType;
  if (row.refresh) headers.refresh = row.refresh;
  if (row.nosniff === "yes") headers["x-content-type-options"] = "nosniff";
  const method = row.method === "HEAD" ? "HEAD" : row.method === "GET" ? "GET" : undefined;
  return {
    url: row.url,
    status: Number(row.status ?? "200"),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
    ...(row.body === undefined ? {} : { body: row.body }),
    ...(method === undefined ? {} : { method }),
  };
}

Given("the resolution fixture responds:", function (this: LinklintWorld, table: DataTable) {
  this.hops = (table.hashes() as unknown as HopRow[]).map(toResponseStep);
});

Given(
  "host {string} resolves to the cloud metadata address",
  function (this: LinklintWorld, hostname: string) {
    this.resolveOverrides[hostname] = "169.254.169.254";
  },
);

// --- When: build the relevant enricher over the fixture and resolve ----------

function transportOptions(world: LinklintWorld) {
  const { harness, transport } = buildFixtureTransport(world.hops, {
    resolveHostTo: world.resolveOverrides,
  });
  world.harness = harness;
  return { transport, authorize: allowAll, now: () => harness.clock.now() };
}

When(
  "I resolve {string} through the redirect-chain enricher",
  async function (this: LinklintWorld, input: string) {
    this.input = input;
    const enricher = createRedirectChainEnricher(transportOptions(this));
    this.result = await inspectAsync(input, { enrichers: [enricher] });
  },
);

When(
  "I resolve {string} through the redirect-chain enricher capped at {int} hops",
  async function (this: LinklintWorld, input: string, maxHops: number) {
    this.input = input;
    const enricher = createRedirectChainEnricher({ ...transportOptions(this), maxHops });
    this.result = await inspectAsync(input, { enrichers: [enricher] });
  },
);

When(
  "I resolve {string} through the redirect-chain enricher using HEAD",
  async function (this: LinklintWorld, input: string) {
    this.input = input;
    const enricher = createRedirectChainEnricher({ ...transportOptions(this), method: "HEAD" });
    this.result = await inspectAsync(input, { enrichers: [enricher] });
  },
);

When(
  "I resolve {string} through the divergence probe",
  async function (this: LinklintWorld, input: string) {
    this.input = input;
    const enricher = createDivergenceProbeEnricher(transportOptions(this));
    this.result = await inspectAsync(input, { enrichers: [enricher] });
  },
);

When(
  "I decode a Microsoft Safe Links wrapper for {string} through the embedded-wrapper enricher",
  async function (this: LinklintWorld, destination: string) {
    this.input = microsoftSafeLink(destination);
    const enricher = createEmbeddedWrapperEnricher({ now: frozenNow });
    this.result = await inspectAsync(this.input, { enrichers: [enricher] });
  },
);

When(
  "I inspect {string} asynchronously with no enrichers",
  async function (this: LinklintWorld, input: string) {
    this.input = input;
    this.result = await inspectAsync(input);
  },
);

// --- Then: resolution-specific assertions ------------------------------------

function outcomes(world: LinklintWorld): EnrichmentOutcome[] {
  return world.result.enrichment?.outcomes ?? [];
}

function allEvidence(world: LinklintWorld) {
  return outcomes(world).flatMap((outcome) => outcome.evidence);
}

Then("checksRun contains {string}", function (this: LinklintWorld, token: string) {
  assert.ok(this.result.checksRun.includes(token), `checksRun missing ${token}`);
});

Then("checksSkipped contains {string}", function (this: LinklintWorld, token: string) {
  assert.ok(this.result.checksSkipped.includes(token), `checksSkipped missing ${token}`);
});

Then(
  "the enrichment outcome subjects are {string}",
  function (this: LinklintWorld, csv: string) {
    assert.deepEqual(
      outcomes(this).map((outcome) => outcome.subject.value),
      csv.split(","),
    );
  },
);

Then("an enrichment outcome subject is {string}", function (this: LinklintWorld, value: string) {
  assert.ok(
    outcomes(this).some((outcome) => outcome.subject.value === value),
    `no outcome for subject ${value}`,
  );
});

Then("an enrichment outcome has cause {string}", function (this: LinklintWorld, code: string) {
  assert.ok(
    outcomes(this).some((outcome) => outcome.cause?.code === code),
    `no outcome with cause ${code}`,
  );
});

Then(
  "an enrichment outcome with status {string} has cause {string}",
  function (this: LinklintWorld, status: string, code: string) {
    assert.ok(
      outcomes(this).some((outcome) => outcome.status === status && outcome.cause?.code === code),
      `no ${status} outcome with cause ${code}`,
    );
  },
);

Then(
  "an enrichment evidence record of type {string} exists",
  function (this: LinklintWorld, type: string) {
    assert.ok(
      allEvidence(this).some((item) => item.type === type),
      `no evidence record of type ${type}`,
    );
  },
);

Then(
  "an enrichment evidence record of type {string} has {string} equal to {string}",
  function (this: LinklintWorld, type: string, key: string, expected: string) {
    const record = allEvidence(this).find((item) => item.type === type);
    assert.ok(record, `no evidence record of type ${type}`);
    const actual = record.payload[key];
    const coerced =
      expected === "true" ? true : expected === "false" ? false : expected;
    assert.deepEqual(actual, coerced);
  },
);

Then(
  "the reasons equal the synchronous inspection of {string}",
  function (this: LinklintWorld, input: string) {
    assert.deepEqual(
      this.result.reasons.map((reason) => reason.code),
      inspect(input).reasons.map((reason) => reason.code),
    );
  },
);

Then(
  "the async result matches the synchronous inspection",
  function (this: LinklintWorld) {
    const sync = inspect(this.input);
    assert.equal(this.result.status, sync.status);
    assert.equal(this.result.score, sync.score);
    assert.deepEqual(
      this.result.reasons.map((reason) => reason.code),
      sync.reasons.map((reason) => reason.code),
    );
    assert.equal(this.result.enrichment, undefined);
  },
);

Then("the fixture transport is exhausted", function (this: LinklintWorld) {
  assert.ok(this.harness, "no fixture harness was built");
  this.harness.assertExhausted();
});

Then(
  "the fixture requests sent the {string} header exactly once as {string}",
  function (this: LinklintWorld, header: string, value: string) {
    assert.ok(this.harness, "no fixture harness was built");
    const sent = this.harness.http.calls
      .map((call) => call.headers[header.toLowerCase()])
      .filter((actual) => actual !== undefined);
    assert.deepEqual(sent, [value], `unexpected ${header} values on the fixture requests`);
  },
);
