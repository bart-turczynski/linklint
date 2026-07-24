/**
 * DNS answer normalization (LINK-diataibn, M9a1).
 *
 * Reduces the four raw {@link DnsAnswer}s (A, AAAA, NS, MX) into one flat,
 * JSON-safe {@link NormalizedDnsState}. It distinguishes every answer state the
 * port can report — authoritative presence, authoritative negatives (NODATA /
 * NXDOMAIN), and operational non-answers (SERVFAIL / REFUSED / timeout / abort /
 * error) — and derives the RFC-defined mail semantic from the MX and address
 * answers together. TTLs are preserved and reduced to a minimum so a caller can
 * reason about record lifetime; none of this scores anything, and no single
 * state proves legitimacy or malice.
 */

import type {
  DnsAddressRecord,
  DnsAnswer,
  DnsAnswerState,
  DnsMxRecord,
  DnsNsRecord,
} from "./dns-types.js";

/**
 * Mail-routing semantic derived from the MX answer and the address fallback.
 *
 * - `explicit-mx`: one or more ordinary MX exchanges.
 * - `null-mx`: RFC 7505 — a single MX with target `"."` and preference `0`; the
 *   domain explicitly accepts NO mail.
 * - `implicit-a-fallback`: no MX records (NODATA) but A/AAAA present, so mail is
 *   delivered to the address per RFC 5321 §5.1.
 * - `no-mail-target`: no MX and no address — nowhere to deliver mail.
 * - `unknown`: the MX query did not authoritatively answer.
 */
export type DnsMailSemantic =
  | "explicit-mx"
  | "null-mx"
  | "implicit-a-fallback"
  | "no-mail-target"
  | "unknown";

/** Normalized address (A/AAAA) answer. */
export interface NormalizedAddressAnswer {
  readonly state: DnsAnswerState;
  readonly addresses: readonly string[];
  /** Minimum TTL across records, or `null` when there are none. */
  readonly ttlSeconds: number | null;
}

/** Normalized NS answer. */
export interface NormalizedNsAnswer {
  readonly state: DnsAnswerState;
  readonly hosts: readonly string[];
  readonly ttlSeconds: number | null;
}

/** Normalized MX answer. */
export interface NormalizedMxAnswer {
  readonly state: DnsAnswerState;
  readonly exchanges: readonly { readonly exchange: string; readonly preference: number }[];
  readonly ttlSeconds: number | null;
}

/** The complete normalized DNS state for one inspected host. */
export interface NormalizedDnsState {
  /** The host whose A/AAAA were queried. */
  readonly host: string;
  /** The name whose NS/MX were queried (registrable domain, or the host). */
  readonly zone: string;
  readonly a: NormalizedAddressAnswer;
  readonly aaaa: NormalizedAddressAnswer;
  readonly ns: NormalizedNsAnswer;
  readonly mx: NormalizedMxAnswer;
  readonly mailSemantic: DnsMailSemantic;
  /** True when at least one A or AAAA address resolved. */
  readonly resolvable: boolean;
  /** True when at least one query returned an authoritative answer (ok/nodata/nxdomain). */
  readonly authoritative: boolean;
  /** Minimum TTL across every record observed, or `null` when none. */
  readonly minTtlSeconds: number | null;
}

const AUTHORITATIVE: ReadonlySet<DnsAnswerState> = new Set(["ok", "nodata", "nxdomain"]);

export interface NormalizeDnsInput {
  readonly host: string;
  readonly zone: string;
  readonly a: DnsAnswer;
  readonly aaaa: DnsAnswer;
  readonly ns: DnsAnswer;
  readonly mx: DnsAnswer;
}

/** Normalize the four raw answers into a single flat DNS-state record. */
export function normalizeDnsState(input: NormalizeDnsInput): NormalizedDnsState {
  const a = normalizeAddress(input.a);
  const aaaa = normalizeAddress(input.aaaa);
  const ns = normalizeNs(input.ns);
  const mx = normalizeMx(input.mx);

  const resolvable = a.addresses.length > 0 || aaaa.addresses.length > 0;
  const mailSemantic = deriveMailSemantic(mx, resolvable);
  const authoritative =
    AUTHORITATIVE.has(a.state) ||
    AUTHORITATIVE.has(aaaa.state) ||
    AUTHORITATIVE.has(ns.state) ||
    AUTHORITATIVE.has(mx.state);
  const minTtlSeconds = minTtl([a.ttlSeconds, aaaa.ttlSeconds, ns.ttlSeconds, mx.ttlSeconds]);

  return { host: input.host, zone: input.zone, a, aaaa, ns, mx, mailSemantic, resolvable, authoritative, minTtlSeconds };
}

function normalizeAddress(answer: DnsAnswer): NormalizedAddressAnswer {
  if (answer.state === "ok" && (answer.type === "A" || answer.type === "AAAA")) {
    const records: readonly DnsAddressRecord[] = answer.addresses;
    return {
      state: "ok",
      addresses: records.map((r) => r.address),
      ttlSeconds: minTtl(records.map((r) => r.ttlSeconds)),
    };
  }
  return { state: answer.state, addresses: [], ttlSeconds: null };
}

function normalizeNs(answer: DnsAnswer): NormalizedNsAnswer {
  if (answer.state === "ok" && answer.type === "NS") {
    const records: readonly DnsNsRecord[] = answer.nameservers;
    return {
      state: "ok",
      hosts: records.map((r) => r.host),
      ttlSeconds: minTtl(records.map((r) => r.ttlSeconds)),
    };
  }
  return { state: answer.state, hosts: [], ttlSeconds: null };
}

function normalizeMx(answer: DnsAnswer): NormalizedMxAnswer {
  if (answer.state === "ok" && answer.type === "MX") {
    const records: readonly DnsMxRecord[] = answer.exchanges;
    // Sort by preference for stable, meaningful ordering; ties keep input order.
    const sorted = [...records].sort((x, y) => x.preference - y.preference);
    return {
      state: "ok",
      exchanges: sorted.map((r) => ({ exchange: r.exchange, preference: r.preference })),
      ttlSeconds: minTtl(records.map((r) => r.ttlSeconds)),
    };
  }
  return { state: answer.state, exchanges: [], ttlSeconds: null };
}

/** RFC 7505 null MX: exactly one exchange whose target is `.` with preference 0. */
function isNullMx(mx: NormalizedMxAnswer): boolean {
  return (
    mx.state === "ok" &&
    mx.exchanges.length === 1 &&
    mx.exchanges[0]!.exchange === "." &&
    mx.exchanges[0]!.preference === 0
  );
}

function deriveMailSemantic(mx: NormalizedMxAnswer, resolvable: boolean): DnsMailSemantic {
  if (isNullMx(mx)) return "null-mx";
  if (mx.state === "ok" && mx.exchanges.length > 0) return "explicit-mx";
  // No usable MX records. An authoritative "no MX" (nodata/nxdomain) falls back
  // to the address per RFC 5321 §5.1; an operational non-answer stays unknown.
  if (mx.state === "nodata" || mx.state === "nxdomain") {
    return resolvable ? "implicit-a-fallback" : "no-mail-target";
  }
  return "unknown";
}

/** Minimum of the finite, non-negative TTLs, or `null` when none are present. */
function minTtl(values: readonly (number | null)[]): number | null {
  let min: number | null = null;
  for (const value of values) {
    if (value === null || !Number.isFinite(value) || value < 0) continue;
    min = min === null ? value : Math.min(min, value);
  }
  return min;
}
