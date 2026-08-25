/**
 * Production DNS resolver port over `node:dns/promises` (LINK-diataibn, M9a1).
 *
 * Implements {@link DnsResolverPort} with a per-query `node:dns` `Resolver`, so a
 * caller `AbortSignal` maps to `resolver.cancel()` and surfaces as an `aborted`
 * answer rather than a thrown rejection. Every c-ares/libuv error code is mapped
 * to an explicit {@link DnsAnswerState}: an authoritative negative (ENOTFOUND /
 * ENODATA) becomes `nxdomain` / `nodata`, a deterministic local rejection
 * (EBADNAME / EBADSTR, plus a name too empty to query at all) becomes
 * `invalid-name`, and an operational failure (ESERVFAIL, EREFUSED, ETIMEOUT,
 * ECANCELLED, or anything else) becomes the matching non-answer state. The resolver never scores and never interprets mail
 * semantics.
 *
 * This file legitimately imports `node:dns` because it lives in `@linklint/online`
 * outside `src/testing/`; the package boundary forbids that import only in the
 * test-support surface.
 */

import { Resolver } from "node:dns/promises";

import type {
  DnsAddressRecord,
  DnsAnswer,
  DnsAnswerState,
  DnsMxRecord,
  DnsNsRecord,
  DnsObservation,
  DnsQuery,
  DnsResolverPort,
  DnssecAnswer,
  DnssecQuery,
} from "./dns-types.js";

const DEFAULT_RESOLVER_NAME = "node:dns";

/**
 * Attempts c-ares makes for one query before it reports ETIMEOUT.
 *
 * Set explicitly, at the value c-ares and `node:dns` already default to, because
 * this is the multiplier in {@link NodeDnsResolverOptions.timeoutMs}'s worst
 * case. Leaving it unset left that multiplier owned by whichever c-ares the host
 * runtime happens to bundle, which is not something a documented figure can rest
 * on. Four attempts is what a UDP resolver wants — a single dropped datagram
 * must not become a `timeout` answer — so the value is unchanged; only its
 * ownership is.
 */
const QUERY_TRIES = 4;

export interface NodeDnsResolverOptions {
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
  /**
   * PER-ATTEMPT c-ares timeout in ms. **Not** a bound on how long `query` runs.
   *
   * c-ares spends this value on ONE attempt, floors it at its own 250 ms
   * MIN_TIMEOUT_MS, doubles it on each pass over the server list, and makes
   * {@link QUERY_TRIES} attempts before answering `timeout`. The cost of one
   * query against a silent server is therefore on the order of
   *
   * ```text
   * (2 ** QUERY_TRIES - 1) * max(250, timeoutMs)  =  15 * max(250, timeoutMs)
   * ```
   *
   * — about 3.75 s at `timeoutMs: 200`, and about 3 s at ANY value at or below
   * the floor, including 1. Measured against a loopback server that answers
   * nothing, on c-ares 1.34.6: 2.2–3.5 s at `timeoutMs` 1, 50 and 250, 6–7 s at
   * 500, 12–15 s at 1000, i.e. 12–15× the base, with one attempt period of slack
   * either way from c-ares' own tick alignment. A value under the floor buys
   * nothing at all: 1 ms, 10 ms and 50 ms each held a single attempt open for
   * ~250 ms.
   *
   * The exact figure belongs to c-ares and moves between its releases, so read
   * this as an order of magnitude rather than a deadline. The hard bound is
   * `DnsQuery.signal`: an abort maps to `resolver.cancel()` and returns
   * `aborted` promptly, and it is what the enrichment runner's own deadline
   * drives when this port is composed through `inspectAsync`.
   */
  readonly timeoutMs?: number;
  /** Resolver identity recorded on the observation. */
  readonly resolverName?: string;
  /**
   * Upstream resolvers to query, as `node:dns` server strings (`"9.9.9.9"`,
   * `"9.9.9.9:1053"`, `"[2620:fe::fe]"`). Defaults to the system configuration.
   *
   * This is the choosing half of {@link resolverName}'s labelling half: a
   * deployment that wants a known resolver rather than whatever the host or
   * container inherited sets both, so the observation names the resolver that
   * was actually queried.
   */
  readonly servers?: readonly string[];
}

/**
 * Build a `node:dns/promises`-backed {@link DnsResolverPort}.
 *
 * Bounded by `DnsQuery.signal`, which is the only hard bound here;
 * {@link NodeDnsResolverOptions.timeoutMs} sizes c-ares' attempts and does not
 * cap the call.
 */
export function createNodeDnsResolver(options: NodeDnsResolverOptions = {}): DnsResolverPort {
  const now = options.now ?? (() => new Date());
  const resolverName = options.resolverName ?? DEFAULT_RESOLVER_NAME;

  return {
    async query(request: DnsQuery): Promise<DnsAnswer> {
      const observation: DnsObservation = { observedAt: now().toISOString(), resolver: resolverName };

      if (request.signal?.aborted === true) {
        return negative("aborted", request, observation);
      }

      // An empty name cannot form a query. c-ares rejects it locally with
      // ENODATA, which stateForError would otherwise take at face value and
      // report as an AUTHORITATIVE "this name has no records" — a claim about
      // DNS reality derived from a query that never happened (LINK-enbiprjm).
      // Guarding here makes the answer deterministic instead of depending on
      // which code the local resolver happens to pick.
      if (request.name === "") {
        return negative("invalid-name", request, observation);
      }

      // `tries` is passed on both paths so the attempt count is this port's,
      // stated, rather than inherited from the runtime (LINK-vlwzmjki).
      const resolver =
        options.timeoutMs !== undefined && options.timeoutMs > 0
          ? new Resolver({ timeout: options.timeoutMs, tries: QUERY_TRIES })
          : new Resolver({ tries: QUERY_TRIES });
      if (options.servers !== undefined && options.servers.length > 0) {
        resolver.setServers([...options.servers]);
      }

      const onAbort = (): void => resolver.cancel();
      request.signal?.addEventListener("abort", onAbort, { once: true });

      try {
        return await runQuery(resolver, request, observation);
      } catch (error) {
        return negative(stateForError(error, request.signal), request, observation);
      } finally {
        request.signal?.removeEventListener("abort", onAbort);
      }
    },

    // Async to satisfy the port's Promise contract; no I/O is honest here (see below).
    async validateDnssec(request: DnssecQuery): Promise<DnssecAnswer> {
      const observation: DnsObservation = { observedAt: now().toISOString(), resolver: resolverName };

      // HONEST LIMITATION: Node's `dns/promises` stub resolver neither exposes the
      // AD (Authenticated Data) bit nor performs DNSSEC chain validation, and it
      // offers no way to request DO/CD or read RRSIG/DNSKEY through this API. There
      // is therefore no observation that could prove `secure` or `bogus`, and we
      // must NOT fabricate one. The only honest verdict a non-validating stub can
      // give is `indeterminate` with `resolverValidates: false`. A validating
      // provider (a DoH/DoT resolver, or a dedicated validating stub) would be a
      // separate port implementation; the injected-port abstraction is what lets
      // tests exercise all four states via deterministic fixtures.
      if (request.signal?.aborted === true) {
        return { state: "indeterminate", name: request.name, resolverValidates: false, unresolved: "aborted", observation };
      }
      return { state: "indeterminate", name: request.name, resolverValidates: false, observation };
    },
  };
}

async function runQuery(
  resolver: Resolver,
  request: DnsQuery,
  observation: DnsObservation,
): Promise<DnsAnswer> {
  switch (request.type) {
    case "A": {
      const rows = await resolver.resolve4(request.name, { ttl: true });
      return okOrNodata("A", request, observation, addressRecords(rows, 4));
    }
    case "AAAA": {
      const rows = await resolver.resolve6(request.name, { ttl: true });
      return okOrNodata("AAAA", request, observation, addressRecords(rows, 6));
    }
    case "NS": {
      const rows = await resolver.resolveNs(request.name);
      const records: DnsNsRecord[] = rows.map((host) => ({ host, ttlSeconds: -1 }));
      return records.length === 0
        ? negative("nodata", request, observation)
        : { type: "NS", state: "ok", nameservers: records, observation };
    }
    case "MX": {
      const rows = await resolver.resolveMx(request.name);
      const records: DnsMxRecord[] = rows.map((row) => ({
        exchange: mxExchange(row.exchange),
        preference: row.priority,
        ttlSeconds: -1,
      }));
      return records.length === 0
        ? negative("nodata", request, observation)
        : { type: "MX", state: "ok", exchanges: records, observation };
    }
  }
}

/**
 * Map a c-ares MX target onto the `DnsMxRecord` contract in `dns-types.ts`.
 *
 * DO NOT copy `row.exchange` raw. c-ares renders the DNS root label as the EMPTY
 * STRING, but the port's documented contract spells it `"."` and that is what
 * `dns-normalize.ts`'s `isNullMx` matches on. Copying the raw value inverted the
 * signal (LINK-kfillkxk): a domain publishing RFC 7505 "I accept no mail at all"
 * was reported as `explicit-mx`, i.e. as having working mail, and `null-mx` was
 * unreachable outside fixtures. `dns-node-live.test.ts` pins this against a real
 * DNS server that answers with the root label on the wire.
 */
function mxExchange(exchange: string): string {
  return exchange === "" ? "." : exchange;
}

function addressRecords(
  rows: readonly { address: string; ttl: number }[],
  family: 4 | 6,
): DnsAddressRecord[] {
  return rows.map((row) => ({ address: row.address, family, ttlSeconds: row.ttl }));
}

function okOrNodata(
  type: "A" | "AAAA",
  request: DnsQuery,
  observation: DnsObservation,
  addresses: DnsAddressRecord[],
): DnsAnswer {
  if (addresses.length === 0) return negative("nodata", request, observation);
  return { type, state: "ok", addresses, observation };
}

/** An answer with no records; the state carries the exact resolver disposition. */
function negative(
  state: Exclude<DnsAnswerState, "ok">,
  request: DnsQuery,
  observation: DnsObservation,
): DnsAnswer {
  return { type: request.type, state, observation };
}

/** Map a `node:dns` rejection to the answer state it represents. */
/**
 * Map a c-ares/libuv error code onto an explicit {@link DnsAnswerState}.
 *
 * Exported for `dns-node.test.ts` only — this table is unreachable from any
 * injected fixture, so pinning it needs the function itself. It is deliberately
 * NOT re-exported from the package index, matching `systemErrorCode` in
 * `transport/node-resolver.ts`.
 *
 * The `default` is `error`, the honest catch-all for a code this port did not
 * anticipate. Codes that would mean this port misused the c-ares API — EBADFLAGS,
 * EBADFAMILY, EBADHINTS, EBADQUERY — are left to it on purpose: the port passes
 * fixed flags and a fixed family, so it cannot produce them, and inventing a
 * mapping for an unreachable path would claim coverage that no test can prove.
 */
export function stateForError(
  error: unknown,
  signal: AbortSignal | undefined,
): Exclude<DnsAnswerState, "ok"> {
  const code = errorCode(error);
  switch (code) {
    case "ENODATA":
      return "nodata";
    case "ENOTFOUND":
    case "ENONAME":
      return "nxdomain";
    case "ESERVFAIL":
    case "EBADRESP":
    case "EFORMERR":
      return "servfail";
    case "EREFUSED":
    case "ECONNREFUSED":
      return "refused";
    case "ETIMEOUT":
      return "timeout";
    // Deterministic LOCAL rejections: c-ares refused to build a query from the
    // name it was given, so no packet left the host and no retry can help.
    // EBADRESP and EFORMERR stay on `servfail` above — those are a server
    // sending garbage, which is a network condition and can differ on a retry.
    case "EBADNAME":
    case "EBADSTR":
      return "invalid-name";
    case "ECANCELLED":
      return signal?.aborted === true ? "aborted" : "timeout";
    default:
      return "error";
  }
}

function errorCode(error: unknown): string | null {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    return typeof code === "string" ? code : null;
  }
  return null;
}
