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
 *
 * `"."` is the ONE spelling of the root label this port emits, and normalizing
 * onto it is the port's obligation. A resolver that renders the root label
 * differently — c-ares, and therefore `node:dns`, renders it as the empty string
 * — must map it here, because the normalizer matches `"."` exactly. A port that
 * passes the raw value through inverts the signal, reporting a domain that
 * accepts no mail as one with working mail (LINK-kfillkxk).
 */
export interface DnsMxRecord {
  readonly exchange: string;
  readonly preference: number;
  readonly ttlSeconds: number;
}

/**
 * The resolver answer states this port distinguishes. Authoritative states
 * (`ok`, `nodata`, `nxdomain`) describe DNS reality; operational states
 * (`servfail`, `refused`, `timeout`, `aborted`, `invalid-name`, `error`) mean the
 * resolver could not answer and the observation is unavailable, never "no
 * records exist".
 *
 * `invalid-name` is the one operational state that is DETERMINISTIC: the
 * resolver rejected the name locally, before any query reached the wire, so
 * nothing about the network changed the answer and no retry can change it
 * either. It exists because the alternatives both lie — `nodata` would assert
 * authoritatively that a name we never queried has no records, and `error`
 * groups a permanent local rejection with the transient failures the enricher
 * reports as retryable (LINK-enbiprjm).
 */
export type DnsAnswerState =
  | "ok"
  | "nodata"
  | "nxdomain"
  | "servfail"
  | "refused"
  | "timeout"
  | "aborted"
  | "invalid-name"
  | "error";

/** The operational (non-authoritative) subset of {@link DnsAnswerState}. */
export type DnsUnresolvedState = Extract<
  DnsAnswerState,
  "servfail" | "refused" | "timeout" | "aborted" | "invalid-name" | "error"
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
 * DNSSEC validation state for a name, per RFC 4035 §5.
 *
 * - `secure`: the name is signed and the resolver validated the chain of trust.
 * - `insecure`: an unsigned / opt-out delegation — the resolver PROVED there is
 *   no DNSSEC for this name. This is NEUTRAL, never risk: absence of DNSSEC is a
 *   deliberate and common operational choice.
 * - `bogus`: signatures were present but validation FAILED. An anomaly worth
 *   recording, but even bogus may be a misconfiguration (expired RRSIG, key
 *   rollover), NEVER proof of malice.
 * - `indeterminate`: the state could not be determined — the resolver does not
 *   validate, the trust path is unknown, or an operational non-answer intervened.
 *   A non-validating resolver is `indeterminate`, NOT `insecure`.
 */
export type DnssecValidationState = "secure" | "insecure" | "bogus" | "indeterminate";

/**
 * The operational reasons a DNSSEC validation could not resolve to an
 * authoritative state and therefore collapsed to `indeterminate`. This mirrors
 * the operational subset of {@link DnsAnswerState} that DNSSEC evaluation can hit.
 */
export type DnssecUnresolvedState = "servfail" | "timeout" | "aborted" | "error";

/** A single DNSSEC validation request. `signal` cancels an in-flight lookup. */
export interface DnssecQuery {
  /** The name whose DNSSEC validation state is evaluated (typically the zone). */
  readonly name: string;
  readonly signal?: AbortSignal;
}

/**
 * A DNSSEC validation observation. It carries exactly the four-valued
 * {@link DnssecValidationState}, whether the answering resolver validates at all,
 * and — when an operational failure forced `indeterminate` — the reason. Absence
 * of DNSSEC surfaces as an authoritative `insecure`, never as a failure.
 */
export interface DnssecAnswer {
  readonly state: DnssecValidationState;
  /** The name that was validated. */
  readonly name: string;
  /** Whether the answering resolver performs DNSSEC validation at all. */
  readonly resolverValidates: boolean;
  /** Present only when an operational non-answer forced `state: "indeterminate"`. */
  readonly unresolved?: DnssecUnresolvedState;
  readonly observation: DnsObservation;
}

/**
 * Provider-scoped DNS resolver port. Injected into the enricher; a deterministic
 * fake in tests, a bounded `node:dns/promises` client in production. Resolves —
 * never rejects — for every DNS-level outcome; only a programming error should
 * throw. Cancellation surfaces as a `state: "aborted"` answer.
 *
 * {@link validateDnssec} extends the same injected port with DNSSEC
 * validation-state evidence (M9a2). It is a distinct method rather than another
 * {@link DnsQueryType} because DNSSEC reports a validation verdict, not a record
 * set, and — like {@link query} — it resolves for every outcome: operational
 * non-answers and cancellation collapse to `indeterminate` (with `unresolved`
 * recorded), never a rejection. DNSSEC state is evidence-only and neutral: only
 * `bogus` is an anomaly, and even that is never a scored finding.
 */
export interface DnsResolverPort {
  query(request: DnsQuery): Promise<DnsAnswer>;
  validateDnssec(request: DnssecQuery): Promise<DnssecAnswer>;
}
