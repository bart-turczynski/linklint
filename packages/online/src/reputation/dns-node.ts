/**
 * Production DNS resolver port over `node:dns/promises` (LINK-diataibn, M9a1).
 *
 * Implements {@link DnsResolverPort} with a per-query `node:dns` `Resolver`, so a
 * caller `AbortSignal` maps to `resolver.cancel()` and surfaces as an `aborted`
 * answer rather than a thrown rejection. Every c-ares/libuv error code is mapped
 * to an explicit {@link DnsAnswerState}: an authoritative negative (ENOTFOUND /
 * ENODATA) becomes `nxdomain` / `nodata`, while an operational failure
 * (ESERVFAIL, EREFUSED, ETIMEOUT, ECANCELLED, or anything else) becomes the
 * matching non-answer state. The resolver never scores and never interprets mail
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

export interface NodeDnsResolverOptions {
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
  /** Per-query timeout in ms, applied through `Resolver({ timeout })`. */
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

/** Build a bounded `node:dns/promises`-backed {@link DnsResolverPort}. */
export function createNodeDnsResolver(options: NodeDnsResolverOptions = {}): DnsResolverPort {
  const now = options.now ?? (() => new Date());
  const resolverName = options.resolverName ?? DEFAULT_RESOLVER_NAME;

  return {
    async query(request: DnsQuery): Promise<DnsAnswer> {
      const observation: DnsObservation = { observedAt: now().toISOString(), resolver: resolverName };

      if (request.signal?.aborted === true) {
        return negative("aborted", request, observation);
      }

      const resolver =
        options.timeoutMs !== undefined && options.timeoutMs > 0
          ? new Resolver({ timeout: options.timeoutMs })
          : new Resolver();
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
function stateForError(error: unknown, signal: AbortSignal | undefined): Exclude<DnsAnswerState, "ok"> {
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
