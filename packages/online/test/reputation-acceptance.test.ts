import { describe, expect, it } from "vitest";

import { inspectAsync } from "linklint";
import type { Enricher } from "linklint";

import {
  createDnsStateEnricher,
  createRdapAgeEnricher,
  createTlsCertificateEnricher,
  DNS_SOURCE_ID,
  RDAP_SOURCE_ID,
  TLS_SOURCE_ID,
  type DnsAnswer,
  type DnsQuery,
  type DnsQueryType,
  type DnsResolverPort,
  type DnssecAnswer,
  type DnssecQuery,
  type RdapBootstrapRegistry,
  type RdapHttpClient,
  type RdapHttpResponse,
} from "../src/reputation/index.js";
import {
  createPhishTankEnricher,
  createPhishTankIndex,
  createUrlhausEnricher,
  createUrlhausIndex,
  PHISHTANK_SOURCE_ID,
  URLHAUS_SOURCE_ID,
  type PhishTankRecord,
  type PhishTankSnapshot,
  type PhishTankSnapshotMetadata,
  type UrlhausRecord,
  type UrlhausSnapshot,
  type UrlhausSnapshotMetadata,
} from "../src/mirrors/index.js";
import { createSafeTlsInspector, type SafeTlsInspector } from "../src/transport/index.js";
import { TransportFixtureHarness, type TransportFixtureScript } from "../src/testing/index.js";
import { handshake } from "./fixtures/tls-certificates.js";

import {
  REPUTATION_CORPUS,
  REPUTATION_FINDING_CODES,
  REPUTATION_SOURCES,
  type DnsRow,
  type PhishTankRow,
  type ReputationCorpusRow,
  type ReputationSource,
  type TlsRow,
  type UrlhausRow,
} from "./corpus/reputation-corpus.js";

/**
 * Layer-3 cross-source acceptance gate (LINK-lbhcpjkj / M10 U2).
 *
 * The runtime mirror of the Layer-2 resolution acceptance gate: it drives the
 * five REAL reputation enrichers through `inspectAsync` over injected fixtures
 * and a labeled corpus, asserting per-row attribution/freshness expectations
 * and an overall precision/recall threshold. Zero live network, fixed clock.
 *
 * Each row targets ONE source with a real fixture; the other four are composed
 * from inert ports so the gate proves the target composes and emits
 * correctly-attributed output while nothing over-scores. The harness builders
 * are written to be reused by U3's cross-source composition properties.
 */
const REPUTATION_PR_THRESHOLD = 1.0;

const NOW_ISO = "2026-07-24T00:00:00.000Z";
const NOW_MS = Date.parse(NOW_ISO);
const now = (): Date => new Date(NOW_ISO);
const DAY = 86_400_000;
const PUBLIC_A = "93.184.216.34";
/** A 1h record lifetime makes a fresh RDAP outcome deterministic. */
const RDAP_LIFETIME_MS = 3_600_000;

const SOURCE_ID: Record<ReputationSource, string> = {
  rdap: RDAP_SOURCE_ID,
  urlhaus: URLHAUS_SOURCE_ID,
  phishtank: PHISHTANK_SOURCE_ID,
  tls: TLS_SOURCE_ID,
  dns: DNS_SOURCE_ID,
};

const CONJUNCTIVE: ReadonlySet<ReputationSource> = new Set<ReputationSource>([
  "rdap",
  "urlhaus",
  "phishtank",
]);

/** The evidence type whose presence marks an evidence-only source's affirmative. */
const AFFIRMATIVE_EVIDENCE: Record<"tls" | "dns", string> = {
  tls: "tls.certificate",
  dns: "dns.records",
};

// ── RDAP fixture (deterministic HTTP client + bootstrap registry) ────────────
const RDAP_REGISTRY: RdapBootstrapRegistry = {
  version: "1.0",
  publication: "2026-01-01T00:00:00Z",
  services: [[["com", "net"], ["https://rdap.verisign.example/v1"]]],
};

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

class OneShotRdapClient implements RdapHttpClient {
  constructor(private readonly response: RdapHttpResponse) {}
  async request(): Promise<RdapHttpResponse> {
    return this.response;
  }
}

/** Inert RDAP: any query is an honest no-hit — never a finding. */
const INERT_RDAP_CLIENT = new OneShotRdapClient(rdapResp(404));

function daysAgo(days: number): string {
  return new Date(NOW_MS - days * DAY).toISOString();
}

// ── URLhaus / PhishTank fixtures (local snapshot indexes) ────────────────────
const FRESH_SNAPSHOT = {
  observedAt: "2026-07-23T23:00:00.000Z",
  expiresAt: "2026-07-24T01:00:00.000Z",
} as const;
const STALE_EXPIRES_AT = "2026-07-23T00:00:00.000Z";

function urlhausSnapshot(row: UrlhausRow): UrlhausSnapshot {
  const records: UrlhausRecord[] =
    row.entry === null
      ? []
      : [
          {
            id: "3001",
            url: row.entry.url,
            dateAdded: "2026-07-23T12:00:00.000Z",
            status: row.entry.status ?? "online",
            lastOnline: NOW_ISO,
            threat: "malware_download",
            tags: ["exe"],
            reporter: "anonymous",
          },
        ];
  const metadata: UrlhausSnapshotMetadata = {
    source: URLHAUS_SOURCE_ID,
    version: "1.0.0",
    etag: '"u1"',
    lastModified: null,
    observedAt: FRESH_SNAPSHOT.observedAt,
    expiresAt: row.stale === true ? STALE_EXPIRES_AT : FRESH_SNAPSHOT.expiresAt,
    recordCount: records.length,
  };
  return { metadata, records };
}

function phishtankSnapshot(row: PhishTankRow): PhishTankSnapshot {
  const records: PhishTankRecord[] =
    row.entry === null
      ? []
      : [
          {
            phishId: "8000001",
            url: row.entry.url,
            detailUrl: "http://www.phishtank.com/phish_detail.php?phish_id=8000001",
            submissionTime: "2026-07-20T12:00:00.000Z",
            verified: row.entry.verified ?? true,
            verificationTime: "2026-07-20T13:00:00.000Z",
            online: row.entry.online ?? true,
            target: "PayPal",
          },
        ];
  const metadata: PhishTankSnapshotMetadata = {
    source: PHISHTANK_SOURCE_ID,
    version: "1.0.0",
    etag: '"p1"',
    lastModified: null,
    observedAt: FRESH_SNAPSHOT.observedAt,
    expiresAt: row.stale === true ? STALE_EXPIRES_AT : FRESH_SNAPSHOT.expiresAt,
    recordCount: records.length,
  };
  return { metadata, records };
}

// ── TLS fixture (safe inspector over checked-in DER) ─────────────────────────
function tlsInspectorFor(row: TlsRow): SafeTlsInspector {
  const host = new URL(row.input).hostname;
  const cert = row.cert!;
  const overrides = {
    ...(cert.chainTrusted !== undefined ? { chainTrusted: cert.chainTrusted } : {}),
    ...(cert.trustErrorCode !== undefined ? { trustErrorCode: cert.trustErrorCode } : {}),
  };
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
        outcome: { value: handshake(cert.leaf, overrides) },
      },
    ],
  };
  const harness = new TransportFixtureHarness(script);
  return createSafeTlsInspector({
    resolver: harness.resolver,
    observer: harness.tlsObserver,
    clock: harness.clock,
  });
}

/** Inert TLS: transport-policy refusal — a skip, never evidence or a finding. */
const INERT_TLS_INSPECTOR: SafeTlsInspector = {
  inspect: async ({ url }) => ({
    status: "blocked",
    subject: { kind: "url", value: url },
    observedAt: NOW_ISO,
    evidence: { type: "tls.attempt", subject: { kind: "url", value: url }, observedAt: NOW_ISO },
    cause: { code: "prohibited-address" },
  }),
};

// ── DNS fixture (injectable resolver port) ───────────────────────────────────
const DNS_OBS = { observedAt: NOW_ISO, resolver: "fake" } as const;

interface DnsScript {
  A?: DnsAnswer;
  NS?: DnsAnswer;
}

class FakeDnsResolver implements DnsResolverPort {
  constructor(private readonly script: DnsScript) {}
  async query(request: DnsQuery): Promise<DnsAnswer> {
    if (request.signal?.aborted === true) {
      return { type: request.type, state: "aborted", observation: DNS_OBS };
    }
    return this.script[request.type as "A" | "NS"] ?? nodata(request.type);
  }
  async validateDnssec(request: DnssecQuery): Promise<DnssecAnswer> {
    return {
      state: "indeterminate",
      name: request.name,
      resolverValidates: false,
      observation: DNS_OBS,
    };
  }
}

function nodata(type: DnsQueryType): DnsAnswer {
  return { type, state: "nodata", observation: DNS_OBS };
}

function dnsResolverFor(row: DnsRow): DnsResolverPort {
  const resolve = row.resolve;
  if (resolve === undefined) return new FakeDnsResolver({});
  const script: DnsScript = {
    A: {
      type: "A",
      state: "ok",
      addresses: resolve.a.map(([address, ttlSeconds]) => ({ address, family: 4, ttlSeconds })),
      observation: DNS_OBS,
    },
  };
  if (resolve.ns !== undefined) {
    script.NS = {
      type: "NS",
      state: "ok",
      nameservers: resolve.ns.map((host) => ({ host, ttlSeconds: -1 })),
      observation: DNS_OBS,
    };
  }
  return new FakeDnsResolver(script);
}

/** Inert DNS: NODATA everywhere — evidence-only, never a finding. */
function inertDnsResolver(): DnsResolverPort {
  return new FakeDnsResolver({});
}

// ── Compose the five real enrichers for one row ──────────────────────────────
export function buildReputationEnrichers(row: ReputationCorpusRow): Enricher[] {
  const rdapClient =
    row.source === "rdap"
      ? new OneShotRdapClient(
          rdapResp(
            200,
            rdapJson(
              new URL(row.input).hostname,
              row.registeredDaysAgo === null ? null : daysAgo(row.registeredDaysAgo),
            ),
          ),
        )
      : INERT_RDAP_CLIENT;
  const rdap = createRdapAgeEnricher({
    client: rdapClient,
    registry: RDAP_REGISTRY,
    now,
    cacheTtlMs: RDAP_LIFETIME_MS,
  });

  const urlhausSnap = row.source === "urlhaus" ? urlhausSnapshot(row) : null;
  const urlhausIndex = urlhausSnap === null ? null : createUrlhausIndex(urlhausSnap);
  const urlhaus = createUrlhausEnricher({ resolveIndex: () => urlhausIndex, now });

  const phishSnap = row.source === "phishtank" ? phishtankSnapshot(row) : null;
  const phishIndex = phishSnap === null ? null : createPhishTankIndex(phishSnap);
  const phishtank = createPhishTankEnricher({ resolveIndex: () => phishIndex, now });

  const inspector =
    row.source === "tls" && row.cert !== undefined ? tlsInspectorFor(row) : INERT_TLS_INSPECTOR;
  const tls = createTlsCertificateEnricher({ inspector, now });

  const resolver = row.source === "dns" ? dnsResolverFor(row) : inertDnsResolver();
  const dns = createDnsStateEnricher({ resolver, now });

  return [rdap, urlhaus, phishtank, tls, dns];
}

export async function runReputationRow(
  row: ReputationCorpusRow,
): Promise<Awaited<ReturnType<typeof inspectAsync>>> {
  return inspectAsync(row.input, { enrichers: buildReputationEnrichers(row) });
}

function affirmativeFired(
  row: ReputationCorpusRow,
  result: Awaited<ReturnType<typeof inspectAsync>>,
): boolean {
  const target = (result.enrichment?.outcomes ?? []).find(
    (outcome) => outcome.sourceId === SOURCE_ID[row.source],
  );
  if (target === undefined) return false;
  if (CONJUNCTIVE.has(row.source)) return target.findings.length > 0;
  const type = AFFIRMATIVE_EVIDENCE[row.source as "tls" | "dns"];
  return target.evidence.some((evidence) => evidence.type === type);
}

// ── Per-row acceptance assertions ────────────────────────────────────────────
describe("L3 reputation cross-source acceptance gate", () => {
  it.each(REPUTATION_CORPUS)(
    "$source/$name composes and emits correctly-attributed output",
    async (row) => {
      const result = await runReputationRow(row);
      const outcomes = result.enrichment?.outcomes ?? [];

      // Fan-in: every one of the five sources produced exactly one outcome.
      expect(outcomes.length, `${row.name}: composed source count`).toBe(5);

      const sid = SOURCE_ID[row.source];
      const target = outcomes.find((outcome) => outcome.sourceId === sid);
      expect(target, `${row.name}: target outcome present`).toBeDefined();
      if (target === undefined) return;

      // Honest outcome status.
      expect(target.status, `${row.name}: status`).toBe(row.expectStatus);

      // Source attribution: declared provenance naming the source under test,
      // a deterministic observedAt, and the descriptor-declared freshness.
      expect(target.provenance.kind).toBe("declared");
      if (target.provenance.kind === "declared") {
        expect(target.provenance.source.name, `${row.name}: outcome attribution`).toBe(sid);
      }
      expect(target.observedAt, `${row.name}: observedAt`).toBe(NOW_ISO);
      if (row.expectFreshness !== undefined) {
        expect(target.freshness.status, `${row.name}: freshness`).toBe(row.expectFreshness);
      }

      // Findings: exactly the expected codes (evidence-only sources → none).
      expect(target.findings.map((finding) => finding.code)).toEqual([...(row.expectReasons ?? [])]);

      // Evidence: expected types present, each attributed to the source.
      const evidenceTypes = target.evidence.map((evidence) => evidence.type);
      for (const type of row.expectEvidence ?? []) {
        expect(evidenceTypes, `${row.name}: evidence ${type}`).toContain(type);
      }
      for (const evidence of target.evidence) {
        expect(evidence.provenance.kind).toBe("declared");
        if (evidence.provenance.kind === "declared") {
          expect(evidence.provenance.source.name, `${row.name}: evidence attribution`).toBe(sid);
        }
        expect(evidence.observedAt, `${row.name}: evidence observedAt`).toBe(NOW_ISO);
      }

      // A successful source registers its check token.
      if (row.expectStatus === "success") {
        expect(result.checksRun, `${row.name}: checksRun`).toContain(`reputation:${sid}`);
      }

      // Non-over-scoring: only the row's expected finding codes may surface in
      // the projected reasons, and no OTHER composed source may fire a finding.
      const reasonCodes = result.reasons.map((reason) => reason.code);
      for (const code of REPUTATION_FINDING_CODES) {
        if ((row.expectReasons ?? []).includes(code)) {
          expect(reasonCodes, `${row.name}: expected ${code}`).toContain(code);
        } else {
          expect(reasonCodes, `${row.name}: over-scored ${code}`).not.toContain(code);
        }
      }
      for (const outcome of outcomes) {
        if (outcome.sourceId === sid) continue;
        expect(outcome.findings, `${row.name}: ${outcome.sourceId} must not fire`).toEqual([]);
      }
    },
  );

  it("classifies every corpus row at or above the precision/recall threshold", async () => {
    // A P/R gate needs both directions represented, per source.
    for (const source of REPUTATION_SOURCES) {
      const rows = REPUTATION_CORPUS.filter((row) => row.source === source);
      expect(rows.some((row) => row.label === "positive"), `${source}: has positive`).toBe(true);
      expect(rows.some((row) => row.label === "negative"), `${source}: has negative`).toBe(true);
    }

    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const row of REPUTATION_CORPUS) {
      const predicted = affirmativeFired(row, await runReputationRow(row));
      const actual = row.label === "positive";
      if (predicted && actual) tp++;
      else if (predicted && !actual) fp++;
      else if (!predicted && actual) fn++;
    }

    const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
    expect(precision).toBeGreaterThanOrEqual(REPUTATION_PR_THRESHOLD);
    expect(recall).toBeGreaterThanOrEqual(REPUTATION_PR_THRESHOLD);
  });
});
