/**
 * Built-in system DNS resolver port, shared by the fetch transport and the TLS
 * inspector so both pin destinations through the same resolution path.
 */

import { lookup } from "node:dns/promises";

import type { DnsAddress, ResolveRequest, ResolverPort, TransportCauseCode } from "./types.js";

class NodeResolverFailure extends Error {
  constructor(readonly code: TransportCauseCode) {
    super("node dns resolution failed");
    this.name = "NodeResolverFailure";
  }
}

class NodeResolverAbortError extends Error {
  constructor() {
    super("node dns resolution aborted");
    this.name = "AbortError";
  }
}

export class NodeResolver implements ResolverPort {
  async resolve(request: ResolveRequest): Promise<readonly DnsAddress[]> {
    try {
      const pending = lookup(request.hostname, { all: true, verbatim: true });
      const answers = await abortable(pending, request.signal);
      return answers.map((answer) => ({
        address: answer.address,
        family: answer.family === 6 ? 6 : 4,
        ttlSeconds: 0,
      }));
    } catch (error) {
      if (error instanceof NodeResolverAbortError) throw error;
      const code = systemErrorCode(error);
      if (code === "ENOTFOUND" || code === "ENODATA") throw new NodeResolverFailure("dns-not-found");
      if (code === "EAI_AGAIN" || code === "ETIMEOUT") throw new NodeResolverFailure("dns-timeout");
      throw new NodeResolverFailure("dns-error");
    }
  }
}

export function systemErrorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : null;
}

async function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) throw new NodeResolverAbortError();
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new NodeResolverAbortError());
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
    void promise.catch(() => undefined);
  }
}
