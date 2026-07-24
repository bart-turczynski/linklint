/**
 * DNSSEC validation-state evidence (LINK-ljjvfcgo, M9a2).
 *
 * The DNS state source emits the zone's DNSSEC validation state as a SECOND
 * attributed `dns.dnssec` artifact alongside `dns.records`. This is evidence-only
 * and neutral: an unsigned (`insecure`) zone is NOT risk, a non-validating
 * resolver is `indeterminate` (never `insecure`), and even a validation-failed
 * (`bogus`) zone is only an anomaly — so NONE of the four states ever projects a
 * finding. These tests exercise all four states plus the operational non-answers
 * (timeout / abort) that collapse to `indeterminate`, using a pure in-test fake
 * resolver: no `node:dns`, no real network, no DNSSEC library.
 */

import { describe, expect, it } from "vitest";
import type { EnrichmentReport, InspectResult } from "linklint";

import {
  assertOnlineSourceContract,
} from "./contract/online-source-contract-kit.js";
import {
  createDnsStateEnricher,
  DNS_SOURCE_DESCRIPTOR,
  type DnsAnswer,
  type DnsAnswerState,
  type DnsQuery,
  type DnsQueryType,
  type DnsResolverPort,
  type DnssecAnswer,
  type DnssecQuery,
  type DnssecUnresolvedState,
  type DnssecValidationState,
} from "../src/reputation/index.js";

const NOW = new Date("2026-07-24T00:00:00.000Z");
const OBS = { observedAt: NOW.toISOString(), resolver: "fake" } as const;

function aOk(address: string): DnsAnswer {
  return { type: "A", state: "ok", addresses: [{ address, family: 4, ttlSeconds: 300 }], observation: OBS };
}

function neg(type: DnsQueryType, state: Exclude<DnsAnswerState, "ok">): DnsAnswer {
  return { type, state, observation: OBS };
}

/**
 * A resolver whose A record is authoritative (so the enricher reaches the success
 * path) and whose DNSSEC answer is fully scripted. Pure and deterministic.
 */
class ScriptedDnssecResolver implements DnsResolverPort {
  readonly dnssecQueries: string[] = [];
  constructor(private readonly dnssec: DnssecAnswer) {}

  async query(request: DnsQuery): Promise<DnsAnswer> {
    if (request.type === "A") return aOk("93.184.216.34");
    return neg(request.type, "nodata");
  }

  async validateDnssec(request: DnssecQuery): Promise<DnssecAnswer> {
    this.dnssecQueries.push(request.name);
    return this.dnssec;
  }
}

function dnssecAnswer(
  name: string,
  state: DnssecValidationState,
  resolverValidates: boolean,
  unresolved?: DnssecUnresolvedState,
): DnssecAnswer {
  return {
    state,
    name,
    resolverValidates,
    ...(unresolved !== undefined ? { unresolved } : {}),
    observation: OBS,
  };
}

function hostResult(host = "example.com"): InspectResult {
  return {
    input: `https://${host}/`,
    parsed: { effectiveHost: host, registrableDomain: host, isIp: false },
    reasons: [],
  } as unknown as InspectResult;
}

async function run(resolver: DnsResolverPort): Promise<EnrichmentReport> {
  const enricher = createDnsStateEnricher({ resolver, now: () => NOW });
  return (await enricher.enrich(hostResult(), { previousOutcomes: [] })) as EnrichmentReport;
}

/** Extract the `dns.dnssec` evidence payload from a success outcome. */
async function dnssecPayload(resolver: DnsResolverPort): Promise<Record<string, unknown>> {
  const outcome = (await run(resolver)).outcomes[0]!;
  expect(outcome.status).toBe("success");
  // No state ever projects a finding — the pin that must hold for every case.
  expect(outcome.findings).toEqual([]);
  const dnssec = outcome.evidence.find((e) => e.type === "dns.dnssec");
  expect(dnssec).toBeDefined();
  return dnssec!.payload as Record<string, unknown>;
}

describe("dns.dnssec evidence — the four validation states", () => {
  it("records a secure (signed and validated) zone without any finding", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "secure", true)),
    );
    expect(payload).toEqual({ name: "example.com", validationState: "secure", resolverValidates: true });
  });

  it("records an insecure (unsigned / opt-out delegation) zone as NEUTRAL, never risk", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "insecure", true)),
    );
    // Absence of DNSSEC is provable and deliberate — it is evidence, not a safety
    // signal and not a risk signal. The state is recorded verbatim.
    expect(payload.validationState).toBe("insecure");
    expect(payload.resolverValidates).toBe(true);
  });

  it("records a bogus (validation-failed) zone as an anomaly but still only evidence", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "bogus", true)),
    );
    // Even bogus may be a misconfiguration, so it is emitted as evidence — the
    // enclosing assertion already proved `findings: []`.
    expect(payload.validationState).toBe("bogus");
  });

  it("records indeterminate when the trust path is unknown", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "indeterminate", true)),
    );
    expect(payload.validationState).toBe("indeterminate");
  });

  it("maps a non-validating resolver to indeterminate — NOT insecure", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "indeterminate", false)),
    );
    expect(payload.validationState).toBe("indeterminate");
    expect(payload.resolverValidates).toBe(false);
  });
});

describe("dns.dnssec evidence — operational non-answers collapse to indeterminate", () => {
  it("records a timeout as indeterminate with the unresolved reason, still no finding", async () => {
    const payload = await dnssecPayload(
      new ScriptedDnssecResolver(dnssecAnswer("example.com", "indeterminate", false, "timeout")),
    );
    expect(payload).toMatchObject({ validationState: "indeterminate", unresolved: "timeout" });
  });

  it("does not fail the whole outcome when DNSSEC is unknown but DNS records were observed", async () => {
    // A servfail on DNSSEC alone must not degrade the enrichment: records are
    // authoritative, so the outcome is success with both artifacts present.
    const resolver = new ScriptedDnssecResolver(
      dnssecAnswer("example.com", "indeterminate", false, "servfail"),
    );
    const outcome = (await run(resolver)).outcomes[0]!;
    expect(outcome.status).toBe("success");
    expect(outcome.evidence.map((e) => e.type)).toEqual(["dns.records", "dns.dnssec"]);
    expect(outcome.findings).toEqual([]);
  });
});

describe("dns.dnssec evidence — provenance and freshness parity", () => {
  it("validates the zone apex and stamps the same provenance and unknown freshness as records", async () => {
    const resolver = new ScriptedDnssecResolver(dnssecAnswer("example.com", "secure", true));
    const outcome = (await run(resolver)).outcomes[0]!;
    expect(resolver.dnssecQueries).toEqual(["example.com"]);
    const dnssec = outcome.evidence.find((e) => e.type === "dns.dnssec")!;
    expect(dnssec.provenance).toMatchObject({ kind: "declared", source: { name: DNS_SOURCE_DESCRIPTOR.id } });
    // A live DNSSEC snapshot has no honest expiry — no stale-cache assertion is
    // made; freshness stays unknown, in parity with the records artifact.
    expect(dnssec.freshness).toEqual({ status: "unknown", expiresAt: null });
    expect(dnssec.observedAt).toBe(NOW.toISOString());
  });

  it("keeps the descriptor compliant with the shared online-source contract", () => {
    assertOnlineSourceContract(DNS_SOURCE_DESCRIPTOR);
    expect(DNS_SOURCE_DESCRIPTOR.evidenceScope).toContain("dns.dnssec");
    expect(DNS_SOURCE_DESCRIPTOR.scoring).toBe("evidence-only");
  });
});
