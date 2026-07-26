import { inspectAsync, type EnrichmentReport, type InspectResult } from "linklint";
import { describe, expect, it } from "vitest";

import {
  createRdapAgeEnricher,
  DEFAULT_YOUNG_DOMAIN_THRESHOLD_DAYS,
  type RdapBootstrapRegistry,
  type RdapHttpClient,
  type RdapHttpResponse,
} from "../src/reputation/index.js";

const registry: RdapBootstrapRegistry = {
  version: "1.0",
  publication: "2026-01-01T00:00:00Z",
  services: [[["com", "net"], ["https://rdap.verisign.example/v1"]]],
};

const NOW = "2026-07-24T00:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const DAY = 86_400_000;

/** Days-ago ISO instant relative to the fixed clock. */
function daysAgo(days: number): string {
  return new Date(NOW_MS - days * DAY).toISOString();
}

function rdapJson(opts: { ldhName?: string; registrationDate?: string | null }): string {
  const events: { eventAction: string; eventDate: string }[] = [];
  if (opts.registrationDate) {
    events.push({ eventAction: "registration", eventDate: opts.registrationDate });
  }
  return JSON.stringify({
    objectClassName: "domain",
    ldhName: opts.ldhName ?? "example.com",
    events,
    entities: [
      { roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar"]]] },
    ],
    nameservers: [{ ldhName: "ns1.example.com" }],
    secureDNS: { delegationSigned: false },
  });
}

class OneShotClient implements RdapHttpClient {
  readonly requests: string[] = [];
  constructor(private readonly response: RdapHttpResponse) {}
  async request({ url }: { url: string }): Promise<RdapHttpResponse> {
    this.requests.push(url);
    return this.response;
  }
}

function resp(status: number, body = ""): RdapHttpResponse {
  return { status, body, headers: {} };
}

/** Minimal InspectResult carrying only the fields the enricher reads. */
function fakeResult(opts: {
  registrableDomain: string | null;
  effectiveHost?: string;
  reasons?: { code: string; suppressed?: boolean }[];
}): InspectResult {
  return {
    input: `http://${opts.effectiveHost ?? opts.registrableDomain ?? "invalid"}`,
    parsed:
      opts.registrableDomain === null && opts.effectiveHost === undefined
        ? null
        : {
            registrableDomain: opts.registrableDomain,
            effectiveHost: opts.effectiveHost ?? opts.registrableDomain,
          },
    reasons: (opts.reasons ?? []).map((r) => ({
      code: r.code,
      layer: "lexical",
      detail: "",
      weight: 1,
      ...(r.suppressed ? { suppressed: true } : {}),
    })),
  } as unknown as InspectResult;
}

/** Run the enricher and narrow its output to the structured report the adapter always returns. */
async function run(
  client: RdapHttpClient,
  result: InspectResult,
  opts: { youngThresholdDays?: number } = {},
): Promise<EnrichmentReport> {
  const enricher = createRdapAgeEnricher({
    client,
    registry,
    now: () => new Date(NOW),
    ...(opts.youngThresholdDays !== undefined ? { youngThresholdDays: opts.youngThresholdDays } : {}),
  });
  return (await enricher.enrich(result, { previousOutcomes: [] })) as EnrichmentReport;
}

describe("createRdapAgeEnricher — conjunctive finding", () => {
  it("fires young_domain_brand_risk only when age is young AND a brand signal is present", async () => {
    const client = new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(10) })));
    const report = await run(
      client,
      fakeResult({ registrableDomain: "paypa1.com", reasons: [{ code: "brand_homoglyph" }] }),
    );
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence[0]?.type).toBe("rdap.domain");
    expect(outcome.findings.map((f) => f.code)).toEqual(["young_domain_brand_risk"]);
    expect(outcome.findings[0]?.confidence).toBe(0.9);
    expect(outcome.evidence[0]?.payload.ageDays).toBe(10);
  });

  it("emits evidence but no finding when young without a brand signal", async () => {
    const client = new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(10) })));
    const report = await run(client, fakeResult({ registrableDomain: "freshsite.com", reasons: [] }));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence).toHaveLength(1);
    expect(outcome.findings).toEqual([]);
  });

  it("does not fire for an ancient shared-hosting parent even with a brand signal", async () => {
    const client = new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(4000) })));
    const report = await run(
      client,
      fakeResult({
        registrableDomain: "blogspot.com",
        effectiveHost: "paypa1.blogspot.com",
        reasons: [{ code: "brand_homoglyph" }],
      }),
    );
    const outcome = report.outcomes[0]!;
    expect(outcome.findings).toEqual([]);
    expect(outcome.evidence[0]?.payload.ageDays).toBe(4000);
  });

  it("treats the threshold as an exclusive boundary", async () => {
    const threshold = DEFAULT_YOUNG_DOMAIN_THRESHOLD_DAYS;
    const brand = [{ code: "brand_homoglyph" }];

    const atThreshold = await run(
      new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(threshold) }))),
      fakeResult({ registrableDomain: "edge.com", reasons: brand }),
    );
    expect(atThreshold.outcomes[0]?.findings).toEqual([]);

    const belowThreshold = await run(
      new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(threshold - 1) }))),
      fakeResult({ registrableDomain: "edge.com", reasons: brand }),
    );
    expect(belowThreshold.outcomes[0]?.findings.map((f) => f.code)).toEqual([
      "young_domain_brand_risk",
    ]);
  });

  it("keeps age unknown when the registration event is missing or redacted", async () => {
    const client = new OneShotClient(resp(200, rdapJson({ registrationDate: null })));
    const report = await run(
      client,
      fakeResult({ registrableDomain: "redacted.com", reasons: [{ code: "brand_homoglyph" }] }),
    );
    const outcome = report.outcomes[0]!;
    expect(outcome.evidence[0]?.payload.ageDays).toBeNull();
    expect(outcome.findings).toEqual([]);
  });

  it("ignores a suppressed brand reason", async () => {
    const client = new OneShotClient(resp(200, rdapJson({ registrationDate: daysAgo(5) })));
    const report = await run(
      client,
      fakeResult({
        registrableDomain: "paypa1.com",
        reasons: [{ code: "brand_homoglyph", suppressed: true }],
      }),
    );
    expect(report.outcomes[0]?.findings).toEqual([]);
  });
});

describe("createRdapAgeEnricher — degraded outcomes", () => {
  const brand = [{ code: "brand_homoglyph" }];

  it("maps a 404 to an honest no-hit", async () => {
    const report = await run(new OneShotClient(resp(404)), fakeResult({ registrableDomain: "gone.com", reasons: brand }));
    expect(report.outcomes[0]?.status).toBe("no-hit");
    expect(report.outcomes[0]?.findings).toEqual([]);
  });

  it("maps an unsupported TLD to a skipped outcome with a cause", async () => {
    const report = await run(new OneShotClient(resp(200)), fakeResult({ registrableDomain: "site.zzz", reasons: brand }));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") expect(outcome.cause.code).toBe("rdap-unsupported-tld");
  });

  it("maps a 5xx to a failure outcome", async () => {
    const report = await run(new OneShotClient(resp(503)), fakeResult({ registrableDomain: "down.com", reasons: brand }));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("failure");
    if (outcome.status === "failure") expect(outcome.cause.code).toBe("rdap-http-error");
  });

  it("skips input with no registrable domain", async () => {
    const report = await run(new OneShotClient(resp(200)), fakeResult({ registrableDomain: null }));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    if (outcome.status === "skipped") expect(outcome.cause.code).toBe("rdap-no-registrable-domain");
  });
});

describe("createRdapAgeEnricher — inspectAsync integration", () => {
  it("projects the finding into reasons without duplicating the lexical brand reason", async () => {
    const client = new OneShotClient(
      resp(200, rdapJson({ ldhName: "paypa1.com", registrationDate: daysAgo(7) })),
    );
    const enricher = createRdapAgeEnricher({ client, registry, now: () => new Date(NOW) });
    const result = await inspectAsync("http://paypa1.com", { enrichers: [enricher] });

    // The chosen input is a digit-fold brand homoglyph; guard the precondition.
    const lexicalBrandReasons = result.reasons.filter((r) => r.code === "brand_homoglyph");
    expect(lexicalBrandReasons).toHaveLength(1);

    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain("young_domain_brand_risk");
    expect(codes.filter((c) => c === "young_domain_brand_risk")).toHaveLength(1);
    expect(client.requests).toEqual(["https://rdap.verisign.example/v1/domain/paypa1.com"]);
  });
});
