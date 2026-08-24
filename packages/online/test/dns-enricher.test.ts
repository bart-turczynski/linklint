import { describe, expect, it } from "vitest";
import type { EnrichmentReport, InspectResult } from "linklint";

import {
  createDnsStateEnricher,
  DNS_SOURCE_ID,
  type DnsAnswer,
  type DnsAnswerState,
  type DnsQuery,
  type DnsQueryType,
  type DnsResolverPort,
  type DnssecAnswer,
  type DnssecQuery,
} from "../src/reputation/index.js";

const NOW = new Date("2026-07-24T00:00:00.000Z");
const OBS = { observedAt: NOW.toISOString(), resolver: "fake" } as const;

/** Per-type scripted answers for one host. Missing types default to NODATA. */
interface Script {
  A?: DnsAnswer;
  AAAA?: DnsAnswer;
  NS?: DnsAnswer;
  MX?: DnsAnswer;
}

function aOk(addresses: readonly [string, number][], family: 4 | 6 = 4): DnsAnswer {
  return {
    type: family === 4 ? "A" : "AAAA",
    state: "ok",
    addresses: addresses.map(([address, ttlSeconds]) => ({ address, family, ttlSeconds })),
    observation: OBS,
  };
}

function nsOk(hosts: readonly string[]): DnsAnswer {
  return { type: "NS", state: "ok", nameservers: hosts.map((host) => ({ host, ttlSeconds: -1 })), observation: OBS };
}

function mxOk(records: readonly [string, number][]): DnsAnswer {
  return {
    type: "MX",
    state: "ok",
    exchanges: records.map(([exchange, preference]) => ({ exchange, preference, ttlSeconds: -1 })),
    observation: OBS,
  };
}

function neg(type: DnsQueryType, state: Exclude<DnsAnswerState, "ok">): DnsAnswer {
  return { type, state, observation: OBS };
}

/** A deterministic, injectable DNS resolver. No `node:dns`, no real network. */
class FakeDnsResolver implements DnsResolverPort {
  readonly queries: { name: string; type: DnsQueryType }[] = [];
  readonly dnssecQueries: string[] = [];
  constructor(
    private readonly script: Script,
    private readonly dnssec?: DnssecAnswer,
  ) {}

  async query(request: DnsQuery): Promise<DnsAnswer> {
    this.queries.push({ name: request.name, type: request.type });
    if (request.signal?.aborted === true) {
      return { type: request.type, state: "aborted", observation: OBS };
    }
    return this.script[request.type] ?? neg(request.type, "nodata");
  }

  async validateDnssec(request: DnssecQuery): Promise<DnssecAnswer> {
    this.dnssecQueries.push(request.name);
    if (request.signal?.aborted === true) {
      return {
        state: "indeterminate",
        name: request.name,
        resolverValidates: false,
        unresolved: "aborted",
        observation: OBS,
      };
    }
    // Default: an honest non-validating resolver reports `indeterminate`.
    return (
      this.dnssec ?? { state: "indeterminate", name: request.name, resolverValidates: false, observation: OBS }
    );
  }
}

function fakeResult(opts: {
  input?: string;
  effectiveHost: string | null;
  registrableDomain?: string | null;
  isIp?: boolean;
}): InspectResult {
  const host = opts.effectiveHost;
  return {
    input: opts.input ?? `https://${host ?? "invalid"}/`,
    parsed:
      host === null
        ? null
        : {
            effectiveHost: host,
            registrableDomain: opts.registrableDomain ?? host,
            isIp: opts.isIp ?? false,
          },
    reasons: [],
  } as unknown as InspectResult;
}

async function run(
  resolver: DnsResolverPort,
  result: InspectResult,
  ctx: { signal?: AbortSignal } = {},
): Promise<EnrichmentReport> {
  const enricher = createDnsStateEnricher({ resolver, now: () => NOW });
  return (await enricher.enrich(result, { previousOutcomes: [], ...ctx })) as EnrichmentReport;
}

const HOST_INPUT = fakeResult({ effectiveHost: "example.com", registrableDomain: "example.com" });

describe("createDnsStateEnricher — evidence", () => {
  it("emits dns.records evidence and never a finding for a resolvable host", async () => {
    const resolver = new FakeDnsResolver({
      A: aOk([["93.184.216.34", 300]]),
      AAAA: aOk([["2606:2800:220:1:248:1893:25c8:1946", 300]], 6),
      NS: nsOk(["ns1.example.com"]),
      MX: mxOk([["mail.example.com", 10]]),
    });
    const report = await run(resolver, HOST_INPUT);

    expect(report.outcomes).toHaveLength(1);
    const outcome = report.outcomes[0]!;
    expect(outcome).toMatchObject({
      sourceId: DNS_SOURCE_ID,
      status: "success",
      subject: { kind: "host", value: "example.com" },
      findings: [],
    });
    expect(outcome.evidence).toHaveLength(2);
    expect(outcome.evidence[0]).toMatchObject({
      type: "dns.records",
      subject: { kind: "host", value: "example.com" },
      provenance: { kind: "declared", source: { name: DNS_SOURCE_ID } },
    });
    // The second artifact is the DNSSEC validation state, evidence-only.
    expect(outcome.evidence[1]).toMatchObject({
      type: "dns.dnssec",
      subject: { kind: "host", value: "example.com" },
      payload: { name: "example.com", validationState: "indeterminate", resolverValidates: false },
    });
    expect(outcome.evidence[0]!.payload).toMatchObject({
      resolvable: true,
      mailSemantic: "explicit-mx",
    });
    // Live DNS observation declares no expiry, TLS-parity.
    expect(outcome.freshness).toEqual({ status: "unknown", expiresAt: null });
  });

  it("queries A/AAAA on the host and NS/MX on the registrable domain", async () => {
    const resolver = new FakeDnsResolver({ A: aOk([["203.0.113.5", 60]]) });
    await run(
      resolver,
      fakeResult({ effectiveHost: "login.paypal.evil.com", registrableDomain: "evil.com" }),
    );
    expect(resolver.queries).toEqual([
      { name: "login.paypal.evil.com", type: "A" },
      { name: "login.paypal.evil.com", type: "AAAA" },
      { name: "evil.com", type: "NS" },
      { name: "evil.com", type: "MX" },
    ]);
  });

  it("treats a flattened CNAME chain (resolver returns terminal A records) as a resolvable host", async () => {
    // resolve4 flattens CNAME hops, so the port simply reports the terminal A set.
    const resolver = new FakeDnsResolver({ A: aOk([["198.51.100.7", 45]]), NS: nsOk(["ns1.host.example"]) });
    const report = await run(resolver, fakeResult({ effectiveHost: "cdn.example.com", registrableDomain: "example.com" }));
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence[0]!.payload).toMatchObject({ resolvable: true, mailSemantic: "implicit-a-fallback" });
    expect((outcome.evidence[0]!.payload.a as { addresses: string[] }).addresses).toEqual(["198.51.100.7"]);
  });

  it("captures dual-stack addresses in the payload", async () => {
    const resolver = new FakeDnsResolver({
      A: aOk([["93.184.216.34", 300]]),
      AAAA: aOk([["2606:2800:220:1:248:1893:25c8:1946", 300]], 6),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect((outcome.evidence[0]!.payload.a as { addresses: string[] }).addresses).toEqual(["93.184.216.34"]);
    expect((outcome.evidence[0]!.payload.aaaa as { addresses: string[] }).addresses).toEqual([
      "2606:2800:220:1:248:1893:25c8:1946",
    ]);
  });

  it("records the null-MX mail semantic without any finding", async () => {
    const resolver = new FakeDnsResolver({ A: aOk([["93.184.216.34", 300]]), MX: mxOk([[".", 0]]) });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.findings).toEqual([]);
    expect(outcome.evidence[0]!.payload.mailSemantic).toBe("null-mx");
  });

  it("emits evidence (never a finding) for an authoritative NXDOMAIN", async () => {
    const resolver = new FakeDnsResolver({
      A: neg("A", "nxdomain"),
      AAAA: neg("AAAA", "nxdomain"),
      NS: neg("NS", "nxdomain"),
      MX: neg("MX", "nxdomain"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.findings).toEqual([]);
    expect(outcome.evidence[0]!.payload).toMatchObject({ resolvable: false, mailSemantic: "no-mail-target" });
  });

  it("emits evidence for an authoritative NODATA answer", async () => {
    const resolver = new FakeDnsResolver({
      A: neg("A", "nodata"),
      AAAA: neg("AAAA", "nodata"),
      NS: nsOk(["ns1.example.com"]),
      MX: neg("MX", "nodata"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect((outcome.evidence[0]!.payload.a as { state: string }).state).toBe("nodata");
  });

  it("derives record TTL expiry in the payload while keeping outcome freshness unknown", async () => {
    const resolver = new FakeDnsResolver({
      A: aOk([["93.184.216.34", 300], ["93.184.216.35", 120]]),
      AAAA: aOk([["2606:2800:220:1:248:1893:25c8:1946", 600]], 6),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.evidence[0]!.payload.minTtlSeconds).toBe(120);
    // observedAt + 120s.
    expect(outcome.evidence[0]!.payload.recordsExpireAt).toBe("2026-07-24T00:02:00.000Z");
    expect(outcome.freshness).toEqual({ status: "unknown", expiresAt: null });
  });
});

describe("createDnsStateEnricher — degraded outcomes are never safety claims", () => {
  it("skips hostless input without a lookup", async () => {
    const resolver = new FakeDnsResolver({});
    const report = await run(resolver, fakeResult({ effectiveHost: null }));
    expect(report.outcomes[0]).toMatchObject({ status: "skipped", cause: { code: "dns-no-host", retryable: false } });
    expect(resolver.queries).toEqual([]);
  });

  it("skips an IP-literal host without a lookup", async () => {
    const resolver = new FakeDnsResolver({});
    const report = await run(
      resolver,
      fakeResult({ effectiveHost: "93.184.216.34", registrableDomain: null, isIp: true }),
    );
    expect(report.outcomes[0]).toMatchObject({ status: "skipped", cause: { code: "dns-not-a-hostname", retryable: false } });
    expect(resolver.queries).toEqual([]);
  });

  it("fails with a source-attributed cause when every query is SERVFAIL", async () => {
    const resolver = new FakeDnsResolver({
      A: neg("A", "servfail"),
      AAAA: neg("AAAA", "servfail"),
      NS: neg("NS", "servfail"),
      MX: neg("MX", "servfail"),
    });
    const report = await run(resolver, HOST_INPUT);
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("failure");
    expect(outcome.evidence).toEqual([]);
    if (outcome.status === "failure") {
      expect(outcome.cause.code).toBe("dns-servfail");
      expect(outcome.cause.retryable).toBe(true);
    }
  });

  it("fails as dns-invalid-name, NOT retryable, when the name is rejected locally", async () => {
    // Every other unresolved reason is retryable; this one cannot be. The name
    // was rejected before a query left the host, so the identical call fails
    // identically forever and retrying is pure waste (LINK-enbiprjm).
    const resolver = new FakeDnsResolver({
      A: neg("A", "invalid-name"),
      AAAA: neg("AAAA", "invalid-name"),
      NS: neg("NS", "invalid-name"),
      MX: neg("MX", "invalid-name"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("failure");
    expect(outcome.evidence).toEqual([]);
    if (outcome.status === "failure") {
      expect(outcome.cause.code).toBe("dns-invalid-name");
      expect(outcome.cause.retryable).toBe(false);
    }
  });

  it("does not let a server-side reason mask a locally rejected name", async () => {
    // invalid-name outranks refused/servfail in UNRESOLVED_PRIORITY: it is the
    // only reason the caller can act on, so a slow or hostile server answering
    // one of the other three queries must not turn it back into "try again".
    const resolver = new FakeDnsResolver({
      A: neg("A", "invalid-name"),
      AAAA: neg("AAAA", "invalid-name"),
      NS: neg("NS", "servfail"),
      MX: neg("MX", "refused"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    if (outcome.status === "failure") {
      expect(outcome.cause.code).toBe("dns-invalid-name");
      expect(outcome.cause.retryable).toBe(false);
    }
  });

  it("fails as dns-refused when the resolver refuses every query", async () => {
    const resolver = new FakeDnsResolver({
      A: neg("A", "refused"),
      AAAA: neg("AAAA", "refused"),
      NS: neg("NS", "refused"),
      MX: neg("MX", "refused"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("failure");
    if (outcome.status === "failure") expect(outcome.cause.code).toBe("dns-refused");
  });

  it("skips (retryable) when a caller AbortSignal cancels every query", async () => {
    const resolver = new FakeDnsResolver({ A: aOk([["93.184.216.34", 300]]) });
    const report = await run(resolver, HOST_INPUT, { signal: AbortSignal.abort() });
    const outcome = report.outcomes[0]!;
    expect(outcome.status).toBe("skipped");
    expect(outcome.evidence).toEqual([]);
    if (outcome.status === "skipped") {
      expect(outcome.cause.code).toBe("dns-caller-aborted");
      expect(outcome.cause.retryable).toBe(true);
    }
  });

  it("still emits evidence when only some queries fail but one is authoritative", async () => {
    const resolver = new FakeDnsResolver({
      A: aOk([["93.184.216.34", 300]]),
      AAAA: neg("AAAA", "servfail"),
      NS: neg("NS", "timeout"),
      MX: neg("MX", "servfail"),
    });
    const outcome = (await run(resolver, HOST_INPUT)).outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence).toHaveLength(2);
    expect((outcome.evidence[0]!.payload.aaaa as { state: string }).state).toBe("servfail");
  });
});
