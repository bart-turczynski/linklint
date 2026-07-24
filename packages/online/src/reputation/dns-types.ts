/**
 * DNS state provider-client types (LINK-diataibn, M9a1).
 *
 * A provider-scoped DNS resolver port used by the evidence-only DNS state
 * enricher. Like the RDAP HTTP client, it is a bare interface injected via the
 * enricher options: a deterministic fake in tests, a bounded `node:dns/promises`
 * implementation (`dns-node.ts`) in production. It is deliberately SEPARATE from
 * the L0 `ResolverPort` (`../transport/types.ts`), which is A/AAAA-only and
 * exists to pin a fetch destination; this port answers A, AAAA, NS, and MX and
 * preserves the exact resolver answer state so nothing degrades silently.
 *
 * DNS state alone is neutral — never a safety or malice claim — so the port only
 * reports what it observed. It never scores and never interprets mail semantics;
 * that is `dns-normalize.ts`'s job.
 */

/** The record types this port can query. */
export type DnsQueryType = "A" | "AAAA" | "NS" | "MX";

/** A single DNS query. `signal` cancels an in-flight lookup, like `RdapHttpRequest`. */
export interface DnsQuery {
  readonly name: string;
  readonly type: DnsQueryType;
  readonly signal?: AbortSignal;
}

/** Where and when an answer was observed; attribution for the emitted evidence. */
export interface DnsObservation {
  /** ISO-8601 instant the answer was observed. */
  readonly observedAt: string;
  /** Opaque resolver identity (for provenance/diagnostics), when known. */
  readonly resolver?: string;
}

/** An A/AAAA address record with its TTL. */
export interface DnsAddressRecord {
  readonly address: string;
  readonly family: 4 | 6;
  readonly ttlSeconds: number;
}

/** An NS delegation record with its TTL. */
export interface DnsNsRecord {
  readonly host: string;
  readonly ttlSeconds: number;
}

/**
 * An MX record with its TTL. RFC 7505 "null MX" is reported faithfully here as a
 * single record with `exchange: "."` and `preference: 0`; recognizing that shape
 * is the normalizer's responsibility, not the port's.
 */
export interface DnsMxRecord {
  readonly exchange: string;
  readonly preference: number;
  readonly ttlSeconds: number;
}

/**
 * The resolver answer states this port distinguishes. Authoritative states
 * (`ok`, `nodata`, `nxdomain`) describe DNS reality; operational states
 * (`servfail`, `refused`, `timeout`, `aborted`, `error`) mean the resolver could
 * not answer and the observation is unavailable, never "no records exist".
 */
export type DnsAnswerState =
  | "ok"
  | "nodata"
  | "nxdomain"
  | "servfail"
  | "refused"
  | "timeout"
  | "aborted"
  | "error";

/** The operational (non-authoritative) subset of {@link DnsAnswerState}. */
export type DnsUnresolvedState = Extract<
  DnsAnswerState,
  "servfail" | "refused" | "timeout" | "aborted" | "error"
>;

interface DnsAnswerBase {
  readonly type: DnsQueryType;
  readonly observation: DnsObservation;
}

/**
 * A single DNS answer. `ok` carries the records for its query type; `nodata` and
 * `nxdomain` are authoritative negatives; the remaining states are operational
 * non-answers with no records.
 */
export type DnsAnswer =
  | (DnsAnswerBase & {
      readonly type: "A" | "AAAA";
      readonly state: "ok";
      readonly addresses: readonly DnsAddressRecord[];
    })
  | (DnsAnswerBase & {
      readonly type: "NS";
      readonly state: "ok";
      readonly nameservers: readonly DnsNsRecord[];
    })
  | (DnsAnswerBase & {
      readonly type: "MX";
      readonly state: "ok";
      readonly exchanges: readonly DnsMxRecord[];
    })
  | (DnsAnswerBase & {
      readonly state: "nodata" | "nxdomain" | DnsUnresolvedState;
    });

/**
 * Provider-scoped DNS resolver port. Injected into the enricher; a deterministic
 * fake in tests, a bounded `node:dns/promises` client in production. Resolves —
 * never rejects — for every DNS-level outcome; only a programming error should
 * throw. Cancellation surfaces as a `state: "aborted"` answer.
 */
export interface DnsResolverPort {
  query(request: DnsQuery): Promise<DnsAnswer>;
}
