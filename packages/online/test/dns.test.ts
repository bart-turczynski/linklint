import { describe, expect, it } from "vitest";

import {
  DNS_RECORDS_EVIDENCE_TYPE,
  DNS_SOURCE_DESCRIPTOR,
  DNS_SOURCE_ID,
  normalizeDnsState,
  type DnsAnswer,
  type DnsAnswerState,
} from "../src/reputation/index.js";
import { assertOnlineSourceContract } from "./contract/online-source-contract-kit.js";

const OBS = { observedAt: "2026-07-24T00:00:00.000Z", resolver: "test" } as const;

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

function mxOk(records: readonly [string, number][], ttl = -1): DnsAnswer {
  return {
    type: "MX",
    state: "ok",
    exchanges: records.map(([exchange, preference]) => ({ exchange, preference, ttlSeconds: ttl })),
    observation: OBS,
  };
}

function neg(type: "A" | "AAAA" | "NS" | "MX", state: Exclude<DnsAnswerState, "ok">): DnsAnswer {
  return { type, state, observation: OBS };
}

describe("DNS_SOURCE_DESCRIPTOR", () => {
  it("satisfies the shared online-source contract", () => {
    assertOnlineSourceContract(DNS_SOURCE_DESCRIPTOR);
  });

  it("is a live-provider, evidence-only, no-credential source disclosing the queried names", () => {
    expect(DNS_SOURCE_DESCRIPTOR.id).toBe(DNS_SOURCE_ID);
    expect(DNS_SOURCE_DESCRIPTOR.dataOrigin).toEqual({ kind: "live-provider", recipient: "dns.resolver" });
    expect(DNS_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["registrable-domain", "host"]);
    expect(DNS_SOURCE_DESCRIPTOR.disclosure.consentRequired).toEqual([]);
    expect(DNS_SOURCE_DESCRIPTOR.credentials).toEqual({ kind: "none" });
    expect(DNS_SOURCE_DESCRIPTOR.scoring).toBe("evidence-only");
    expect(DNS_SOURCE_DESCRIPTOR.evidenceScope).toEqual([DNS_RECORDS_EVIDENCE_TYPE]);
    // A live DNS snapshot declares no honest expiry (TTL is evidence data only).
    expect(DNS_SOURCE_DESCRIPTOR.freshness).toEqual({ declaresExpiry: false, staleWhenExpired: false });
    expect(DNS_SOURCE_DESCRIPTOR.noMatchSemantics).toBe("absence-is-not-safety");
  });
});

describe("normalizeDnsState — mail semantics", () => {
  const base = { host: "example.com", zone: "example.com" };

  it("reports explicit-mx for ordinary MX records, sorted by preference", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300]]),
      aaaa: neg("AAAA", "nodata"),
      ns: nsOk(["ns1.example.com"]),
      mx: mxOk([["mail2.example.com", 20], ["mail1.example.com", 10]]),
    });
    expect(state.mailSemantic).toBe("explicit-mx");
    expect(state.mx.exchanges).toEqual([
      { exchange: "mail1.example.com", preference: 10 },
      { exchange: "mail2.example.com", preference: 20 },
    ]);
  });

  it("recognizes RFC 7505 null MX (single '.' target, preference 0)", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300]]),
      aaaa: neg("AAAA", "nodata"),
      ns: nsOk(["ns1.example.com"]),
      mx: mxOk([[".", 0]]),
    });
    expect(state.mailSemantic).toBe("null-mx");
  });

  it("falls back to implicit-a-fallback when MX is NODATA but A/AAAA resolve", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300]]),
      aaaa: aOk([["2606:2800:220:1:248:1893:25c8:1946", 300]], 6),
      ns: nsOk(["ns1.example.com"]),
      mx: neg("MX", "nodata"),
    });
    expect(state.mailSemantic).toBe("implicit-a-fallback");
    expect(state.resolvable).toBe(true);
  });

  it("reports no-mail-target when there is neither MX nor an address", () => {
    const state = normalizeDnsState({
      ...base,
      a: neg("A", "nxdomain"),
      aaaa: neg("AAAA", "nxdomain"),
      ns: neg("NS", "nxdomain"),
      mx: neg("MX", "nxdomain"),
    });
    expect(state.mailSemantic).toBe("no-mail-target");
    expect(state.resolvable).toBe(false);
    // An authoritative NXDOMAIN is a real observation, not an operational failure.
    expect(state.authoritative).toBe(true);
  });

  it("leaves mail semantics unknown when the MX query did not authoritatively answer", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300]]),
      aaaa: neg("AAAA", "nodata"),
      ns: nsOk(["ns1.example.com"]),
      mx: neg("MX", "servfail"),
    });
    expect(state.mailSemantic).toBe("unknown");
  });
});

describe("normalizeDnsState — addresses, TTL, and authority", () => {
  const base = { host: "example.com", zone: "example.com" };

  it("captures dual-stack A + AAAA addresses", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300]]),
      aaaa: aOk([["2606:2800:220:1:248:1893:25c8:1946", 300]], 6),
      ns: neg("NS", "nodata"),
      mx: neg("MX", "nodata"),
    });
    expect(state.a.addresses).toEqual(["93.184.216.34"]);
    expect(state.aaaa.addresses).toEqual(["2606:2800:220:1:248:1893:25c8:1946"]);
    expect(state.resolvable).toBe(true);
  });

  it("selects the minimum TTL across every record and skips unknown (-1) TTLs", () => {
    const state = normalizeDnsState({
      ...base,
      a: aOk([["93.184.216.34", 300], ["93.184.216.35", 120]]),
      aaaa: aOk([["2606:2800:220:1:248:1893:25c8:1946", 600]], 6),
      ns: nsOk(["ns1.example.com"]), // ttl unknown (-1) — must not become the min
      mx: mxOk([["mail.example.com", 10]]), // ttl unknown (-1)
    });
    expect(state.a.ttlSeconds).toBe(120);
    expect(state.aaaa.ttlSeconds).toBe(600);
    expect(state.ns.ttlSeconds).toBeNull();
    expect(state.mx.ttlSeconds).toBeNull();
    expect(state.minTtlSeconds).toBe(120);
  });

  it("is non-authoritative when every query is an operational non-answer", () => {
    const state = normalizeDnsState({
      ...base,
      a: neg("A", "servfail"),
      aaaa: neg("AAAA", "servfail"),
      ns: neg("NS", "timeout"),
      mx: neg("MX", "refused"),
    });
    expect(state.authoritative).toBe(false);
    expect(state.minTtlSeconds).toBeNull();
  });
});
