import { describe, expect, it } from "vitest";

import { inspectAsync } from "linklint";
import type { Enricher, InspectResult } from "linklint";

import {
  createDnsStateEnricher,
  createRdapAgeEnricher,
  createTlsCertificateEnricher,
  DNS_SOURCE_ID,
  RDAP_SOURCE_ID,
  TLS_SOURCE_ID,
  type DnsAnswer,
  type DnsQuery,
  type DnsResolverPort,
  type DnssecAnswer,
  type DnssecQuery,
  type RdapBootstrapRegistry,
  type RdapHttpClient,
  type RdapHttpRequest,
  type RdapHttpResponse,
} from "../src/reputation/index.js";
import {
  createPhishTankEnricher,
  createPhishTankIndex,
  createUrlhausEnricher,
  createUrlhausIndex,
  PHISHTANK_SOURCE_DESCRIPTOR,
  PHISHTANK_SOURCE_ID,
  URLHAUS_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_ID,
  type PhishTankRecord,
  type PhishTankSnapshot,
  type UrlhausRecord,
  type UrlhausSnapshot,
} from "../src/mirrors/index.js";
import { createSafeTlsInspector, type SafeTlsInspector } from "../src/transport/index.js";
import { TransportFixtureHarness, type TransportFixtureScript } from "../src/testing/index.js";
import { createOnlineSecret, REDACTED_SECRET } from "../src/sources/index.js";
import { handshake } from "./fixtures/tls-certificates.js";

/**
 * Layer-3 cross-source COMPOSITION properties (LINK-lbhcpjkj / M10 U3).
 *
 * U2 proved each of the five real reputation enrichers composes and emits
 * correctly-attributed output while the other four stay inert. U3 proves the
 * MULTI-active-source interactions U2 deferred: that several sources firing at
 * once compose ADDITIVELY without double-counting, that one source degrading does
 * not corrupt the others, and that composed disclosure never exceeds any single
 * source's descriptor. All fixtures are canned; fixed clock; zero network.
 *
 * These builders deliberately drive SEVERAL sources live at once (unlike U2's
 * single-live-source harness), composing the public factories directly.
 */

const NOW_ISO = "2026-07-24T00:00:00.000Z";
const NOW_MS = Date.parse(NOW_ISO);
const now = (): Date => new Date(NOW_ISO);
const DAY = 86_400_000;
const PUBLIC_A = "93.184.216.34";
const RDAP_LIFETIME_MS = 3_600_000;

const RDAP_TOKEN = `reputation:${RDAP_SOURCE_ID}`;
const URLHAUS_TOKEN = `reputation:${URLHAUS_SOURCE_ID}`;
const PHISHTANK_TOKEN = `reputation:${PHISHTANK_SOURCE_ID}`;
const TLS_TOKEN = `reputation:${TLS_SOURCE_ID}`;
const DNS_TOKEN = `reputation:${DNS_SOURCE_ID}`;

const RDAP_REGISTRY: RdapBootstrapRegistry = {
  version: "1.0",
  publication: "2026-01-01T00:00:00Z",
  services: [[["com", "net", "example"], ["https://rdap.verisign.example/v1"]]],
};

const FRESH_SNAPSHOT = {
  observedAt: "2026-07-23T23:00:00.000Z",
  expiresAt: "2026-07-24T01:00:00.000Z",
} as const;

// ── RDAP fixtures (recording + throwing HTTP clients) ────────────────────────
function rdapResp(status: number, body = ""): RdapHttpResponse {
  return { status, body, headers: {} };
}

function rdapJson(ldhName: string, registrationDate: string | null): string {
  const events: { eventAction: string; eventDate: string }[] = [];
  if (registrationDate !== null) {
    events.push({ eventAction: "registration", eventDate: registrationDate });
  }
  return JSON.stringify({
    objectClassName: "domain",
    ldhName,
    events,
    entities: [
      { roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar"]]] },
    ],
    nameservers: [{ ldhName: `ns1.${ldhName}` }],
    secureDNS: { delegationSigned: false },
  });
}

function daysAgo(days: number): string {
  return new Date(NOW_MS - days * DAY).toISOString();
}

/** Records every RDAP request URL so composed disclosure can be inspected. */
class RecordingRdapClient implements RdapHttpClient {
  readonly requestedUrls: string[] = [];
  constructor(private readonly response: RdapHttpResponse) {}
  async request(request: RdapHttpRequest): Promise<RdapHttpResponse> {
    this.requestedUrls.push(request.url);
    return this.response;
  }
}

/** An RDAP endpoint that throws on every request — models a hard provider fault. */
class ThrowingRdapClient implements RdapHttpClient {
  readonly requestedUrls: string[] = [];
  async request(request: RdapHttpRequest): Promise<RdapHttpResponse> {
    this.requestedUrls.push(request.url);
    throw new Error("connect ECONNREFUSED rdap.verisign.example:443");
  }
}

// ── URLhaus / PhishTank snapshots (local mirror indexes) ─────────────────────
function urlhausSnapshotFor(url: string): UrlhausSnapshot {
  const records: UrlhausRecord[] = [
    {
      id: "3001",
      url,
      dateAdded: "2026-07-23T12:00:00.000Z",
      status: "online",
      lastOnline: NOW_ISO,
      threat: "malware_download",
      tags: ["exe"],
      reporter: "anonymous",
    },
  ];
  return {
    metadata: {
      source: URLHAUS_SOURCE_ID,
      version: "1.0.0",
      etag: '"u1"',
      lastModified: null,
      observedAt: FRESH_SNAPSHOT.observedAt,
      expiresAt: FRESH_SNAPSHOT.expiresAt,
      recordCount: records.length,
    },
    records,
  };
}

/** A fresh but empty URLhaus snapshot: every lookup is an honest no-hit. */
function emptyUrlhausSnapshot(): UrlhausSnapshot {
  return {
    metadata: {
      source: URLHAUS_SOURCE_ID,
      version: "1.0.0",
      etag: '"u0"',
      lastModified: null,
      observedAt: FRESH_SNAPSHOT.observedAt,
      expiresAt: FRESH_SNAPSHOT.expiresAt,
      recordCount: 0,
    },
    records: [],
  };
}

function phishtankSnapshotFor(url: string): PhishTankSnapshot {
  const records: PhishTankRecord[] = [
    {
      phishId: "8000001",
      url,
      detailUrl: "http://www.phishtank.com/phish_detail.php?phish_id=8000001",
      submissionTime: "2026-07-20T12:00:00.000Z",
      verified: true,
      verificationTime: "2026-07-20T13:00:00.000Z",
      online: true,
      target: "PayPal",
    },
  ];
  return {
    metadata: {
      source: PHISHTANK_SOURCE_ID,
      version: "1.0.0",
      etag: '"p1"',
      lastModified: null,
      observedAt: FRESH_SNAPSHOT.observedAt,
      expiresAt: FRESH_SNAPSHOT.expiresAt,
      recordCount: records.length,
    },
    records,
  };
}

/** A fresh but empty PhishTank snapshot: every lookup is an honest no-hit. */
function emptyPhishtankSnapshot(): PhishTankSnapshot {
  return {
    metadata: {
      source: PHISHTANK_SOURCE_ID,
      version: "1.0.0",
      etag: '"p0"',
      lastModified: null,
      observedAt: FRESH_SNAPSHOT.observedAt,
      expiresAt: FRESH_SNAPSHOT.expiresAt,
      recordCount: 0,
    },
    records: [],
  };
}

// ── TLS fixture (safe inspector over checked-in DER) ─────────────────────────
interface TlsFixture {
  readonly inspector: SafeTlsInspector;
  readonly harness: TransportFixtureHarness;
}

/** A live TLS inspector observing `host:443` normally; records the connect target. */
function tlsFixtureFor(host: string): TlsFixture {
  const script: TransportFixtureScript = {
    startTime: NOW_ISO,
    resolver: [
      {
        hostname: host,
        outcome: { value: [{ address: PUBLIC_A, family: 4 as const, ttlSeconds: 60 }] },
      },
    ],
    tlsObserver: [
      {
        expect: { hostname: host, address: PUBLIC_A, port: 443, serverName: host },
        outcome: { value: handshake("valid") },
      },
    ],
  };
  const harness = new TransportFixtureHarness(script);
  const inspector = createSafeTlsInspector({
    resolver: harness.resolver,
    observer: harness.tlsObserver,
    clock: harness.clock,
  });
  return { inspector, harness };
}

// ── DNS fixture (recording resolver port) ────────────────────────────────────
const DNS_OBS = { observedAt: NOW_ISO, resolver: "fake" } as const;

/** Resolves a host normally (A ok, NS ok) and records every queried NAME. */
class RecordingDnsResolver implements DnsResolverPort {
  readonly queriedNames: string[] = [];
  readonly dnssecNames: string[] = [];
  async query(request: DnsQuery): Promise<DnsAnswer> {
    this.queriedNames.push(request.name);
    if (request.signal?.aborted === true) {
      return { type: request.type, state: "aborted", observation: DNS_OBS };
    }
    if (request.type === "A") {
      return {
        type: "A",
        state: "ok",
        addresses: [{ address: PUBLIC_A, family: 4, ttlSeconds: 300 }],
        observation: DNS_OBS,
      };
    }
    if (request.type === "NS") {
      return {
        type: "NS",
        state: "ok",
        nameservers: [{ host: `ns1.${request.name}`, ttlSeconds: -1 }],
        observation: DNS_OBS,
      };
    }
    return { type: request.type, state: "nodata", observation: DNS_OBS };
  }
  async validateDnssec(request: DnssecQuery): Promise<DnssecAnswer> {
    this.dnssecNames.push(request.name);
    return {
      state: "indeterminate",
      name: request.name,
      resolverValidates: false,
      observation: DNS_OBS,
    };
  }
}

// ── Composition builder: several real sources live at once ───────────────────
interface CompositionSpec {
  readonly input: string;
  /** RDAP behaviour: a young registration, a throwing endpoint, or an honest 404. */
  readonly rdap: "young" | "throw" | "no-hit";
  /** URLhaus: exact-match this URL, an empty snapshot, or omit the source. */
  readonly urlhaus?: { readonly url: string } | "empty" | "omit";
  /** PhishTank: exact-match this URL, an empty snapshot, or omit the source. */
  readonly phishtank?: { readonly url: string } | "empty" | "omit";
  readonly tls?: boolean;
  readonly dns?: boolean;
}

interface Composition {
  readonly enrichers: Enricher[];
  readonly rdapClient: RecordingRdapClient | ThrowingRdapClient;
  readonly tls: TlsFixture | null;
  readonly dnsResolver: RecordingDnsResolver | null;
}

function buildComposition(spec: CompositionSpec): Composition {
  const host = new URL(spec.input).hostname;

  const rdapClient: RecordingRdapClient | ThrowingRdapClient =
    spec.rdap === "throw"
      ? new ThrowingRdapClient()
      : new RecordingRdapClient(
          spec.rdap === "young"
            ? rdapResp(200, rdapJson(host, daysAgo(7)))
            : rdapResp(404),
        );
  const rdap = createRdapAgeEnricher({
    terms: { commercialMode: "commercial" },
    client: rdapClient,
    registry: RDAP_REGISTRY,
    now,
    cacheTtlMs: RDAP_LIFETIME_MS,
  });

  const enrichers: Enricher[] = [rdap];

  const urlhausSpec = spec.urlhaus ?? "omit";
  if (urlhausSpec !== "omit") {
    const snapshot = urlhausSpec === "empty" ? emptyUrlhausSnapshot() : urlhausSnapshotFor(urlhausSpec.url);
    const index = createUrlhausIndex(snapshot);
    enrichers.push(createUrlhausEnricher({ terms: { commercialMode: "fair-use", acceptAttribution: true }, resolveIndex: () => index, now }));
  }

  const phishtankSpec = spec.phishtank ?? "omit";
  if (phishtankSpec !== "omit") {
    const snapshot =
      phishtankSpec === "empty" ? emptyPhishtankSnapshot() : phishtankSnapshotFor(phishtankSpec.url);
    const index = createPhishTankIndex(snapshot);
    enrichers.push(createPhishTankEnricher({ terms: { commercialMode: "fair-use", acceptAttribution: true }, resolveIndex: () => index, now }));
  }

  let tls: TlsFixture | null = null;
  if (spec.tls === true) {
    tls = tlsFixtureFor(host);
    enrichers.push(createTlsCertificateEnricher({ terms: { commercialMode: "commercial" }, inspector: tls.inspector, now }));
  }

  let dnsResolver: RecordingDnsResolver | null = null;
  if (spec.dns === true) {
    dnsResolver = new RecordingDnsResolver();
    enrichers.push(createDnsStateEnricher({ terms: { commercialMode: "commercial" }, resolver: dnsResolver, now }));
  }

  return { enrichers, rdapClient, tls, dnsResolver };
}

function run(spec: CompositionSpec): Promise<InspectResult> {
  return inspectAsync(spec.input, { enrichers: buildComposition(spec).enrichers });
}

/** Probabilistic OR over the reason weights, mirroring core's `aggregate()`. */
function probabilisticOr(reasons: readonly { readonly weight: number }[]): number {
  let inverse = 1;
  for (const reason of reasons) {
    if (reason.weight > 0) inverse *= 1 - reason.weight;
  }
  return 1 - inverse;
}

function reasonCodes(result: InspectResult): string[] {
  return result.reasons.map((reason) => reason.code);
}

function findingCodesAcrossOutcomes(result: InspectResult): string[] {
  return (result.enrichment?.outcomes ?? []).flatMap((outcome) =>
    outcome.findings.map((finding) => finding.code),
  );
}

function outcomeFor(result: InspectResult, sourceId: string) {
  return (result.enrichment?.outcomes ?? []).find((outcome) => outcome.sourceId === sourceId);
}

const THREE_FINDING_CODES = [
  "young_domain_brand_risk",
  "malware_url_listed",
  "verified_phish_listed",
] as const;

// The single input that legitimately trips RDAP + URLhaus + PhishTank at once: a
// young brand-homoglyph domain whose EXACT URL is also listed in both mirrors.
const TRIPLE_URL = "https://paypa1.com/login";

// ── A. Additive composition / non-over-scoring (the core property) ───────────
describe("L3 composition — additive, non-over-scoring", () => {
  it("three sources firing at once: each finding appears exactly once, no reason double-counted", async () => {
    const result = await run({
      input: TRIPLE_URL,
      rdap: "young",
      urlhaus: { url: TRIPLE_URL },
      phishtank: { url: TRIPLE_URL },
      tls: true,
      dns: true,
    });

    // Fan-in: all five sources produced an outcome.
    expect((result.enrichment?.outcomes ?? []).map((o) => o.sourceId).sort()).toEqual(
      [RDAP_SOURCE_ID, URLHAUS_SOURCE_ID, PHISHTANK_SOURCE_ID, TLS_SOURCE_ID, DNS_SOURCE_ID].sort(),
    );

    // Each of the three distinct online findings is emitted EXACTLY once — no
    // source double-emits and no source poaches another's finding.
    const findingCounts = tally(findingCodesAcrossOutcomes(result));
    for (const code of THREE_FINDING_CODES) {
      expect(findingCounts.get(code), `finding ${code} once`).toBe(1);
    }

    // The no-double-count invariant: grouped by code, every reason appears ≤ 1.
    const codeCounts = tally(reasonCodes(result));
    for (const [code, count] of codeCounts) {
      expect(count, `reason ${code} not duplicated`).toBe(1);
    }

    // Additive, not duplicative: the lexical brand reason AND RDAP's conjunctive
    // reputation reason are BOTH present as distinct codes (per the reason-code
    // doc, young_domain_brand_risk "never duplicates the lexical brand reason").
    expect(reasonCodes(result)).toContain("brand_homoglyph");
    expect(reasonCodes(result)).toContain("young_domain_brand_risk");

    // The composed score is exactly the probabilistic-OR of the DISTINCT reason
    // weights — no over-scoring from a duplicated or double-weighted signal.
    expect(result.score).not.toBeNull();
    expect(result.score).toBe(probabilisticOr(result.reasons));

    // Evidence-only sources are present but weightless: TLS/DNS emit their
    // evidence, yet contribute NO finding.
    const tls = outcomeFor(result, TLS_SOURCE_ID);
    const dns = outcomeFor(result, DNS_SOURCE_ID);
    expect(tls?.evidence.map((e) => e.type)).toContain("tls.certificate");
    expect(dns?.evidence.map((e) => e.type)).toContain("dns.records");
    expect(tls?.findings).toEqual([]);
    expect(dns?.findings).toEqual([]);
  });

  it("evidence-only sources cannot move the score (byte-identical with and without TLS+DNS)", async () => {
    const withEvidence = await run({
      input: TRIPLE_URL,
      rdap: "young",
      urlhaus: { url: TRIPLE_URL },
      phishtank: { url: TRIPLE_URL },
      tls: true,
      dns: true,
    });
    const withoutEvidence = await run({
      input: TRIPLE_URL,
      rdap: "young",
      urlhaus: { url: TRIPLE_URL },
      phishtank: { url: TRIPLE_URL },
    });

    // TLS + DNS carry weight 0, so registering them cannot change the score.
    expect(withEvidence.score).toBe(withoutEvidence.score);
    expect(withEvidence.severity).toBe(withoutEvidence.severity);

    // The evidence sources really were live in the first run (present but weightless).
    expect(outcomeFor(withEvidence, TLS_SOURCE_ID)?.status).toBe("success");
    expect(outcomeFor(withEvidence, DNS_SOURCE_ID)?.status).toBe("success");
    expect(outcomeFor(withoutEvidence, TLS_SOURCE_ID)).toBeUndefined();
    expect(outcomeFor(withoutEvidence, DNS_SOURCE_ID)).toBeUndefined();
  });

  it("weightless invariance is discriminating on a NON-saturated score", async () => {
    // No mirror hits: reasons are brand_homoglyph (0.5), ascii_homoglyph (0.2)
    // and young_domain_brand_risk (0.5) → score 1−(.5)(.8)(.5)=0.8, strictly < 1.
    // A saturated (1.0) score could hide an evidence source nudging the ceiling;
    // this one leaves room, so the invariance below actually has teeth.
    const withEvidence = await run({ input: TRIPLE_URL, rdap: "young", tls: true, dns: true });
    const withoutEvidence = await run({ input: TRIPLE_URL, rdap: "young" });

    expect(withEvidence.score).toBeGreaterThan(0);
    expect(withEvidence.score).toBeLessThan(1);
    expect(withEvidence.score).toBe(withoutEvidence.score);
    expect(withEvidence.score).toBe(probabilisticOr(withEvidence.reasons));

    // Distinct codes compose additively; still no duplicate reason code.
    const codeCounts = tally(reasonCodes(withEvidence));
    for (const [code, count] of codeCounts) {
      expect(count, `reason ${code} not duplicated`).toBe(1);
    }
    expect(reasonCodes(withEvidence)).toEqual(
      expect.arrayContaining(["brand_homoglyph", "young_domain_brand_risk"]),
    );
  });
});

// ── B. Degraded composition ──────────────────────────────────────────────────
describe("L3 composition — degraded", () => {
  const MALWARE_URL = "https://malware.example/a.exe";

  it("an RDAP failure does not corrupt the other four sources", async () => {
    const composition = buildComposition({
      input: MALWARE_URL,
      rdap: "throw",
      urlhaus: { url: MALWARE_URL },
      phishtank: "empty",
      tls: true,
      dns: true,
    });

    let result: InspectResult | undefined;
    await expect(
      (async () => {
        result = await inspectAsync(MALWARE_URL, { enrichers: composition.enrichers });
      })(),
    ).resolves.toBeUndefined();
    if (result === undefined) throw new Error("unreachable");

    // The failing source is recorded as a `failure` outcome with a structured
    // cause — never a throw, never a silent clean.
    const rdap = outcomeFor(result, RDAP_SOURCE_ID);
    expect(rdap?.status).toBe("failure");
    expect(rdap?.cause?.code).toBe("rdap-network-error");
    expect(rdap?.findings).toEqual([]);

    // The URLhaus finding is unaffected — still emitted and still scored.
    expect(outcomeFor(result, URLHAUS_SOURCE_ID)?.findings.map((f) => f.code)).toEqual([
      "malware_url_listed",
    ]);
    expect(reasonCodes(result)).toContain("malware_url_listed");
    expect(result.score).toBe(1); // malware_url_listed carries weight 1.

    // The evidence-only sources still observed normally.
    expect(outcomeFor(result, TLS_SOURCE_ID)?.status).toBe("success");
    expect(outcomeFor(result, DNS_SOURCE_ID)?.status).toBe("success");
    expect(outcomeFor(result, PHISHTANK_SOURCE_ID)?.status).toBe("no-hit");

    // checksRun / checksSkipped partition the five composed sources: the four
    // healthy sources ran; only the degraded RDAP source is skipped.
    expect(result.checksRun).toEqual(
      expect.arrayContaining([URLHAUS_TOKEN, PHISHTANK_TOKEN, TLS_TOKEN, DNS_TOKEN]),
    );
    expect(result.checksRun).not.toContain(RDAP_TOKEN);
    expect(result.checksSkipped).toContain(RDAP_TOKEN);
  });
});

// ── C. Composed disclosure = M2, and no secret leak ──────────────────────────
describe("L3 composition — disclosure and secret containment", () => {
  it("each source discloses exactly what its descriptor declares — nothing broader", async () => {
    const composition = buildComposition({
      input: TRIPLE_URL,
      rdap: "young",
      urlhaus: { url: TRIPLE_URL },
      phishtank: { url: TRIPLE_URL },
      tls: true,
      dns: true,
    });
    const result = await inspectAsync(TRIPLE_URL, { enrichers: composition.enrichers });
    const host = "paypa1.com"; // registrable domain == host for this apex input.

    // RDAP: the only egress is the registrable domain to the RDAP endpoint. The
    // request URL names the registry and the domain, and NEVER the input path.
    const rdapClient = composition.rdapClient as RecordingRdapClient;
    expect(rdapClient.requestedUrls.length).toBeGreaterThan(0);
    for (const url of rdapClient.requestedUrls) {
      expect(url.startsWith("https://rdap.verisign.example/")).toBe(true);
      expect(url).toContain(host);
      expect(url).not.toContain("/login");
      expect(url).not.toContain("login");
    }

    // DNS: only the host/zone names are sent to the resolver — never a URL/path.
    const dns = composition.dnsResolver!;
    for (const name of [...dns.queriedNames, ...dns.dnssecNames]) {
      expect(name).toBe(host);
    }

    // TLS: the connection target is exactly host:443 with SNI = host — nothing
    // broader (no path, no port widening).
    const tlsCalls = composition.tls!.harness.tlsObserver.calls;
    expect(tlsCalls.length).toBe(1);
    for (const call of tlsCalls) {
      expect(call.hostname).toBe(host);
      expect(call.serverName).toBe(host);
      expect(call.port).toBe(443);
    }
    // Exact-order fixtures fully consumed: no extra, broader connection happened.
    composition.tls!.harness.assertExhausted();

    // Caller-owned mirrors make NO enrich-time egress: they have no network port
    // to call, and their descriptors declare `sends: ["none"]`.
    expect(URLHAUS_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["none"]);
    expect(PHISHTANK_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["none"]);

    // Sanity: the composed run still fired all three findings over these ports.
    expect(new Set(findingCodesAcrossOutcomes(result))).toEqual(new Set(THREE_FINDING_CODES));
  });

  it("the composed result never leaks a BYOK mirror secret", async () => {
    // Caller-held BYOK credentials for the two mirror feeds, wrapped so they can
    // never serialize into any sink. They are held ALONGSIDE the composed run.
    const urlhausAuthKey = createOnlineSecret("URLHAUS-AUTHKEY-3f9a2b7c-do-not-leak");
    const phishtankAppKey = createOnlineSecret("PHISHTANK-APPKEY-8d1e4f60-do-not-leak");

    // The wrapper redacts on every incidental path.
    expect(JSON.stringify(urlhausAuthKey)).toBe(JSON.stringify(REDACTED_SECRET));
    expect(`${phishtankAppKey}`).toBe(REDACTED_SECRET);

    const result = await run({
      input: TRIPLE_URL,
      rdap: "young",
      urlhaus: { url: TRIPLE_URL },
      phishtank: { url: TRIPLE_URL },
      tls: true,
      dns: true,
    });

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("URLHAUS-AUTHKEY-3f9a2b7c-do-not-leak");
    expect(serialized).not.toContain("PHISHTANK-APPKEY-8d1e4f60-do-not-leak");
    // The raw values are only ever reachable through the audited reveal() path.
    expect(urlhausAuthKey.reveal()).toBe("URLHAUS-AUTHKEY-3f9a2b7c-do-not-leak");
  });
});

function tally(codes: readonly string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const code of codes) counts.set(code, (counts.get(code) ?? 0) + 1);
  return counts;
}
