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
} from "./dns-types.js";

const DEFAULT_RESOLVER_NAME = "node:dns";

export interface NodeDnsResolverOptions {
  /** Observation clock; defaults to `Date`. */
  readonly now?: () => Date;
  /** Per-query timeout in ms, applied through `Resolver({ timeout })`. */
  readonly timeoutMs?: number;
  /** Resolver identity recorded on the observation. */
  readonly resolverName?: string;
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
        exchange: row.exchange,
        preference: row.priority,
        ttlSeconds: -1,
      }));
      return records.length === 0
        ? negative("nodata", request, observation)
        : { type: "MX", state: "ok", exchanges: records, observation };
    }
  }
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
