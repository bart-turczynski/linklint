import type { TlsCertificateFixture } from "../fixtures/tls-certificates.js";

/**
 * Labeled Layer 3 reputation corpus (LINK-lbhcpjkj / M10 U2). The single shared
 * fixture consumed by the cross-source acceptance harness
 * (`reputation-acceptance.test.ts`).
 *
 * Each row exercises exactly ONE of the five real reputation sources through
 * `inspectAsync` with all five enrichers composed. The row carries a binary
 * `label`:
 *  - "positive" — the source under test MUST emit its affirmative signal: a
 *    conjunctive source (`rdap`/`urlhaus`/`phishtank`) fires its finding, and an
 *    evidence-only source (`tls`/`dns`) emits its evidence artifact.
 *  - "negative" — an honest no-match: the source under test contributes NO
 *    finding and no affirmative evidence of a match.
 *
 * The FOUR sources a row does not target are driven from inert fixtures by the
 * harness (empty snapshot, 404 RDAP, prohibited-address TLS, NODATA DNS) so the
 * gate proves the target source composes and emits correctly-attributed output
 * without any other source over-contributing. Multi-source interaction and
 * degraded-composition properties are U3's concern; every row here is minimal
 * and single-source.
 *
 * Every fixture is declarative: the harness translates each spec into the real
 * injected port (RDAP HTTP client, URLhaus/PhishTank index, safe TLS inspector
 * over checked-in DER, or DNS resolver). No live network, fixed clock.
 */

export type ReputationSource = "rdap" | "urlhaus" | "phishtank" | "tls" | "dns";
export type ReputationLabel = "positive" | "negative";

/** The affirmative-signal finding codes owned by the reputation sources. */
export const REPUTATION_FINDING_CODES = [
  "young_domain_brand_risk",
  "malware_url_listed",
  "verified_phish_listed",
] as const;

export type ReputationFindingCode = (typeof REPUTATION_FINDING_CODES)[number];

interface RowBase {
  readonly source: ReputationSource;
  readonly name: string;
  readonly label: ReputationLabel;
  readonly input: string;
  /** Expected status of the target source's outcome. */
  readonly expectStatus: "success" | "no-hit" | "skipped" | "failure";
  /** Finding codes the target outcome MUST project (conjunctive positives). */
  readonly expectReasons?: readonly ReputationFindingCode[];
  /** Evidence types the target outcome MUST carry. */
  readonly expectEvidence?: readonly string[];
  /** Declared freshness status of the target outcome; asserted when present. */
  readonly expectFreshness?: "fresh" | "stale" | "unknown";
}

/** RDAP registration-age fixture: how long ago the registrable domain was registered. */
export interface RdapRow extends RowBase {
  readonly source: "rdap";
  readonly registeredDaysAgo: number | null;
}

/** URLhaus mirror fixture: a single canonical entry, or `null` for an empty snapshot. */
export interface UrlhausRow extends RowBase {
  readonly source: "urlhaus";
  readonly entry: { readonly url: string; readonly status?: "online" | "offline" } | null;
  readonly stale?: boolean;
}

/** PhishTank mirror fixture: a single canonical entry, or `null` for an empty snapshot. */
export interface PhishTankRow extends RowBase {
  readonly source: "phishtank";
  readonly entry:
    | { readonly url: string; readonly verified?: boolean; readonly online?: boolean }
    | null;
  readonly stale?: boolean;
}

/** TLS fixture: the leaf DER certificate to replay; omitted for a non-HTTPS skip. */
export interface TlsRow extends RowBase {
  readonly source: "tls";
  readonly cert?: {
    readonly leaf: TlsCertificateFixture;
    readonly chainTrusted?: boolean;
    readonly trustErrorCode?: string | null;
  };
}

/** DNS fixture: authoritative answers; omitted for an IP-literal / hostless skip. */
export interface DnsRow extends RowBase {
  readonly source: "dns";
  readonly resolve?: {
    readonly a: readonly (readonly [string, number])[];
    readonly ns?: readonly string[];
  };
}

export type ReputationCorpusRow = RdapRow | UrlhausRow | PhishTankRow | TlsRow | DnsRow;

// ── RDAP (conjunctive: young registration AND lexical brand signal) ──────────
const rdapRows: readonly RdapRow[] = [
  {
    source: "rdap",
    name: "rdap-young-brand-homoglyph",
    label: "positive",
    // A digit-fold homoglyph of a brand → inspect emits `brand_homoglyph`.
    input: "http://paypa1.com",
    registeredDaysAgo: 7,
    expectStatus: "success",
    expectReasons: ["young_domain_brand_risk"],
    expectEvidence: ["rdap.domain"],
    expectFreshness: "fresh",
  },
  {
    source: "rdap",
    name: "rdap-young-without-brand-signal",
    label: "negative",
    // Young registration but NO lexical brand signal → the conjunction fails.
    input: "http://freshsite.com",
    registeredDaysAgo: 10,
    expectStatus: "success",
    expectReasons: [],
    expectEvidence: ["rdap.domain"],
    expectFreshness: "fresh",
  },
];

// ── URLhaus (conjunctive: exact online URL within a fresh snapshot) ──────────
const URLHAUS_HIT = "http://malware.example/a.exe";
const urlhausRows: readonly UrlhausRow[] = [
  {
    source: "urlhaus",
    name: "urlhaus-online-exact-match",
    label: "positive",
    input: URLHAUS_HIT,
    entry: { url: URLHAUS_HIT, status: "online" },
    expectStatus: "success",
    expectReasons: ["malware_url_listed"],
    expectEvidence: ["urlhaus.match"],
    expectFreshness: "fresh",
  },
  {
    source: "urlhaus",
    name: "urlhaus-path-miss",
    label: "negative",
    // Clean sibling path; the listed URL is present but never broadens to it.
    input: "http://malware.example/not-listed.exe",
    entry: { url: URLHAUS_HIT, status: "online" },
    expectStatus: "no-hit",
    expectReasons: [],
    expectEvidence: [],
  },
];

// ── PhishTank (conjunctive: verified + online exact URL within a fresh snapshot) ─
const PHISHTANK_HIT = "http://evil.example/login";
const phishtankRows: readonly PhishTankRow[] = [
  {
    source: "phishtank",
    name: "phishtank-verified-online-match",
    label: "positive",
    input: PHISHTANK_HIT,
    entry: { url: PHISHTANK_HIT, verified: true, online: true },
    expectStatus: "success",
    expectReasons: ["verified_phish_listed"],
    expectEvidence: ["phishtank.match"],
    expectFreshness: "fresh",
  },
  {
    source: "phishtank",
    name: "phishtank-path-miss",
    label: "negative",
    input: "http://evil.example/clean",
    entry: { url: PHISHTANK_HIT, verified: true, online: true },
    expectStatus: "no-hit",
    expectReasons: [],
    expectEvidence: [],
  },
];

// ── TLS (evidence-only: certificate observation, never a finding) ────────────
const tlsRows: readonly TlsRow[] = [
  {
    source: "tls",
    name: "tls-valid-certificate-evidence",
    label: "positive",
    input: "https://example.com/login",
    cert: { leaf: "valid" },
    expectStatus: "success",
    expectReasons: [],
    expectEvidence: ["tls.certificate"],
    expectFreshness: "unknown",
  },
  {
    source: "tls",
    name: "tls-non-https-no-observation",
    label: "negative",
    // Non-HTTPS input → the source withholds all evidence (no observation).
    input: "http://example.com/login",
    expectStatus: "skipped",
    expectReasons: [],
    expectEvidence: [],
  },
];

// ── DNS (evidence-only: resolution state, never a finding) ───────────────────
const dnsRows: readonly DnsRow[] = [
  {
    source: "dns",
    name: "dns-resolvable-host-evidence",
    label: "positive",
    input: "https://example.com/",
    resolve: { a: [["93.184.216.34", 300]], ns: ["ns1.example.com"] },
    expectStatus: "success",
    expectReasons: [],
    expectEvidence: ["dns.records", "dns.dnssec"],
    expectFreshness: "unknown",
  },
  {
    source: "dns",
    name: "dns-ip-literal-no-lookup",
    label: "negative",
    // An IP-literal host is not a name to resolve → the source withholds evidence.
    input: "https://93.184.216.34/",
    expectStatus: "skipped",
    expectReasons: [],
    expectEvidence: [],
  },
];

export const REPUTATION_CORPUS: readonly ReputationCorpusRow[] = [
  ...rdapRows,
  ...urlhausRows,
  ...phishtankRows,
  ...tlsRows,
  ...dnsRows,
];

export const REPUTATION_SOURCES: readonly ReputationSource[] = [
  "rdap",
  "urlhaus",
  "phishtank",
  "tls",
  "dns",
];
