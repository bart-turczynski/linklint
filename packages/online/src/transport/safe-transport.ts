import { isIP } from "node:net";

import { addressesEqual, classifyTransportAddress } from "./address.js";
import {
  ContentDecompressionError,
  decodeResponseBody,
  DecompressedLimitError,
  UnsupportedContentEncodingError,
} from "./decompression.js";
import { destinationHeaders } from "./headers.js";
import {
  resolveTransportPolicy,
  type TransportPolicy,
} from "./policy.js";
import type {
  DnsAddress,
  SafeFetchBlocked,
  SafeFetchIncomplete,
  SafeFetchOutcome,
  SafeFetchRequest,
  SafeFetchSuccess,
  SafeTransport,
  SafeTransportPorts,
  SafeTransportSession,
  TransportBudgetUsage,
  TransportCauseCode,
  TransportEvidence,
  TransportProtocol,
} from "./types.js";

export interface CreateSafeTransportOptions extends SafeTransportPorts {
  readonly policy?: Partial<TransportPolicy>;
}

interface AttemptState {
  subject: string;
  readonly hop: number;
  protocol?: TransportProtocol;
  hostname?: string;
  port?: number;
  resolvedAddresses?: readonly string[];
  selectedAddress?: string;
}

type OperationPhase = "dns" | "connect" | "tls" | "http" | "decompression";

class OperationError extends Error {
  constructor(
    readonly phase: OperationPhase,
    readonly original: unknown,
  ) {
    super("transport operation failed");
  }
}

class BudgetError extends Error {
  constructor(readonly code: TransportCauseCode) {
    super("transport budget exceeded");
  }
}

class DeadlineError extends Error {}

export function createSafeTransport(options: CreateSafeTransportOptions): SafeTransport {
  const policy = resolveTransportPolicy(options.policy);
  const ports: SafeTransportPorts = {
    resolver: options.resolver,
    connector: options.connector,
    http: options.http,
    clock: options.clock,
  };
  return {
    createSession: () => new SafeSession(ports, policy),
  };
}

class SafeSession implements SafeTransportSession {
  private readonly startedAtMs: number;
  private hops = 0;
  private encodedBytes = 0;
  private decompressedBytes = 0;

  constructor(
    private readonly ports: SafeTransportPorts,
    private readonly policy: TransportPolicy,
  ) {
    this.startedAtMs = ports.clock.now().getTime();
  }

  get usage(): TransportBudgetUsage {
    return {
      hops: this.hops,
      encodedBytes: this.encodedBytes,
      decompressedBytes: this.decompressedBytes,
      elapsedMs: Math.max(0, this.ports.clock.now().getTime() - this.startedAtMs),
    };
  }

  async fetch(request: SafeFetchRequest): Promise<SafeFetchOutcome> {
    const nextHop = this.hops + 1;
    const state: AttemptState = { subject: request.url, hop: nextHop };

    if (
      request.authorization?.kind !== "destination-fetch" ||
      request.authorization.url !== request.url
    ) {
      return this.blocked(state, "authorization-required");
    }
    if (nextHop > this.policy.maxHops) {
      return this.incomplete(state, "hop-limit", { maxHops: this.policy.maxHops });
    }
    if (request.signal?.aborted) return this.incomplete(state, "caller-aborted");

    const remainingTimeMs = this.remainingTimeMs();
    if (remainingTimeMs <= 0) return this.incomplete(state, "timeout");

    this.hops = nextHop;
    const operationController = new AbortController();
    const timerController = new AbortController();
    let timedOut = false;
    const onCallerAbort = () => operationController.abort();
    request.signal?.addEventListener("abort", onCallerAbort, { once: true });

    const work = this.execute(request, state, operationController.signal);
    const deadline = this.ports.clock
      .sleep(remainingTimeMs, timerController.signal)
      .then(() => {
        timedOut = true;
        operationController.abort();
        throw new DeadlineError();
      });

    try {
      return await Promise.race([work, deadline]);
    } catch (error) {
      if (timedOut || error instanceof DeadlineError) return this.incomplete(state, "timeout");
      if (request.signal?.aborted) return this.incomplete(state, "caller-aborted");
      if (error instanceof BudgetError) {
        return this.incomplete(state, error.code, budgetDetails(error.code, this.policy));
      }
      if (error instanceof OperationError) {
        return this.incomplete(state, operationCause(error));
      }
      return this.incomplete(state, "http-error");
    } finally {
      timerController.abort();
      request.signal?.removeEventListener("abort", onCallerAbort);
      void work.catch(() => undefined);
      void deadline.catch(() => undefined);
    }
  }

  private async execute(
    request: SafeFetchRequest,
    state: AttemptState,
    signal: AbortSignal,
  ): Promise<SafeFetchOutcome> {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return this.blocked(state, "invalid-url");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return this.blocked(state, "unsupported-scheme", { scheme: url.protocol });
    }
    if (request.method !== undefined && request.method !== "GET" && request.method !== "HEAD") {
      return this.blocked(state, "unsupported-method");
    }
    if (url.username !== "" || url.password !== "") {
      return this.blocked(state, "url-credentials");
    }

    url.hash = "";
    state.subject = url.href;
    state.protocol = url.protocol;
    state.hostname = unbracket(url.hostname);
    state.port = effectivePort(url);

    const addresses = await this.resolveAddresses(state.hostname, signal);
    if (signal.aborted) throw new OperationError("dns", { code: "dns-timeout" });
    state.resolvedAddresses = addresses.map(({ address }) => address);
    const malformed = validateAddresses(addresses);
    if (malformed) throw new OperationError("dns", { code: "dns-malformed" });

    for (const answer of addresses) {
      const decision = classifyTransportAddress(answer.address);
      if (!decision.allowed) {
        return this.blocked(state, "prohibited-address", {
          address: answer.address,
          category: decision.category ?? "invalid",
        });
      }
    }

    const selected = addresses[0]!;
    state.selectedAddress = selected.address;
    let connectionId: string | undefined;
    try {
      const connection = await wrapOperation(
        "connect",
        this.ports.connector.connect({
          protocol: state.protocol,
          hostname: state.hostname,
          address: selected.address,
          port: state.port,
          ...(state.protocol === "https:" ? { serverName: state.hostname } : {}),
          signal,
        }),
      );
      connectionId = connection.id;
      if (signal.aborted) throw new OperationError("connect", { code: "connect-timeout" });
      if (
        connection.protocol !== state.protocol ||
        connection.remotePort !== state.port ||
        !addressesEqual(selected.address, connection.remoteAddress)
      ) {
        throw new OperationError("connect", { code: "connection-address-mismatch" });
      }
      if (
        state.protocol === "https:" &&
        (!connection.tls?.authorized || connection.tls.serverName !== state.hostname)
      ) {
        throw new OperationError("tls", { code: "tls-certificate" });
      }

      const response = await wrapOperation(
        "http",
        this.ports.http.request({
          connectionId,
          url: url.href,
          method: request.method ?? "GET",
          headers: destinationHeaders(url.host, request.headers),
          signal,
        }),
      );
      if (signal.aborted) throw new OperationError("http", { code: "http-timeout" });
      if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
        throw new OperationError("http", { code: "http-malformed" });
      }

      const encoded = await wrapOperation("http", this.readEncodedBody(response.body));
      if (signal.aborted) throw new OperationError("http", { code: "http-timeout" });
      const remainingDecoded = this.policy.maxDecompressedBytes - this.decompressedBytes;
      let body: Uint8Array;
      try {
        body = decodeResponseBody(encoded, response.headers, remainingDecoded);
      } catch (error) {
        if (error instanceof DecompressedLimitError) {
          this.decompressedBytes = this.policy.maxDecompressedBytes;
          throw new BudgetError("decompressed-response-too-large");
        }
        if (error instanceof UnsupportedContentEncodingError) {
          throw new OperationError("decompression", error);
        }
        if (error instanceof ContentDecompressionError) {
          throw new OperationError("decompression", error);
        }
        throw error;
      }
      this.decompressedBytes += body.byteLength;

      return this.success(state, {
        url: url.href,
        status: response.status,
        headers: response.headers,
        body,
        encodedBytes: encoded.byteLength,
        decompressedBytes: body.byteLength,
      });
    } finally {
      if (connectionId !== undefined) {
        try {
          await this.ports.connector.close(connectionId);
        } catch {
          // Closing a consumed/aborted socket is best-effort and never leaks an
          // implementation-specific error into the structured outcome.
        }
      }
    }
  }

  private async resolveAddresses(
    hostname: string,
    signal: AbortSignal,
  ): Promise<readonly DnsAddress[]> {
    const family = isIP(hostname);
    if (family === 4 || family === 6) {
      return [{ address: hostname, family, ttlSeconds: 0 }];
    }
    const addresses = await wrapOperation(
      "dns",
      this.ports.resolver.resolve({ hostname, signal }),
    );
    if (addresses.length === 0) throw new OperationError("dns", { code: "dns-not-found" });
    return addresses;
  }

  private async readEncodedBody(body: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let responseBytes = 0;
    for await (const chunk of body) {
      if (!(chunk instanceof Uint8Array)) {
        throw new OperationError("http", { code: "http-malformed" });
      }
      responseBytes += chunk.byteLength;
      this.encodedBytes += chunk.byteLength;
      if (this.encodedBytes > this.policy.maxResponseBytes) {
        this.encodedBytes = this.policy.maxResponseBytes;
        throw new BudgetError("response-too-large");
      }
      chunks.push(new Uint8Array(chunk));
    }
    const joined = new Uint8Array(responseBytes);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return joined;
  }

  private remainingTimeMs(): number {
    const elapsed = this.ports.clock.now().getTime() - this.startedAtMs;
    return this.policy.maxTotalTimeMs - Math.max(0, elapsed);
  }

  private success(
    state: AttemptState,
    response: SafeFetchSuccess["response"],
  ): SafeFetchSuccess {
    const observedAt = this.ports.clock.now().toISOString();
    return {
      status: "success",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      response,
    };
  }

  private blocked(
    state: AttemptState,
    code: SafeFetchBlocked["cause"]["code"],
    details?: SafeFetchBlocked["cause"]["details"],
  ): SafeFetchBlocked {
    const observedAt = this.ports.clock.now().toISOString();
    return {
      status: "blocked",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      cause: details === undefined ? { code } : { code, details },
    };
  }

  private incomplete(
    state: AttemptState,
    code: SafeFetchIncomplete["cause"]["code"],
    details?: SafeFetchIncomplete["cause"]["details"],
  ): SafeFetchIncomplete {
    const observedAt = this.ports.clock.now().toISOString();
    return {
      status: "incomplete",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      cause: details === undefined ? { code } : { code, details },
    };
  }
}

async function wrapOperation<T>(phase: OperationPhase, promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (error) {
    if (error instanceof OperationError || error instanceof BudgetError) throw error;
    throw new OperationError(phase, error);
  }
}

function validateAddresses(addresses: readonly DnsAddress[]): boolean {
  return addresses.some((answer) => {
    const family = isIP(answer.address);
    return (
      family !== answer.family ||
      (family !== 4 && family !== 6) ||
      !Number.isFinite(answer.ttlSeconds) ||
      answer.ttlSeconds < 0
    );
  });
}

function effectivePort(url: URL): number {
  if (url.port !== "") return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

function unbracket(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function evidence(state: AttemptState, observedAt: string): TransportEvidence {
  return {
    type: "transport.attempt",
    subject: { kind: "url", value: state.subject },
    observedAt,
    hop: state.hop,
    ...(state.protocol === undefined ? {} : { protocol: state.protocol }),
    ...(state.hostname === undefined ? {} : { hostname: state.hostname }),
    ...(state.port === undefined ? {} : { port: state.port }),
    ...(state.resolvedAddresses === undefined
      ? {}
      : { resolvedAddresses: state.resolvedAddresses }),
    ...(state.selectedAddress === undefined ? {} : { selectedAddress: state.selectedAddress }),
  };
}

function operationCause(error: OperationError): TransportCauseCode {
  const stableCode = errorCode(error.original);
  if (stableCode) return stableCode;
  if (error.phase === "dns") return "dns-error";
  if (error.phase === "connect") return "connect-error";
  if (error.phase === "tls") return "tls-handshake";
  if (error.phase === "decompression") {
    return error.original instanceof UnsupportedContentEncodingError
      ? "unsupported-content-encoding"
      : "decompression-error";
  }
  return "http-error";
}

function errorCode(error: unknown): TransportCauseCode | null {
  if (typeof error !== "object" || error === null || !("code" in error)) return null;
  const code = error.code;
  return typeof code === "string" && STABLE_OPERATION_CODES.has(code as TransportCauseCode)
    ? (code as TransportCauseCode)
    : null;
}

const STABLE_OPERATION_CODES = new Set<TransportCauseCode>([
  "dns-not-found",
  "dns-timeout",
  "dns-malformed",
  "connect-refused",
  "connect-timeout",
  "connection-address-mismatch",
  "tls-handshake",
  "tls-certificate",
  "http-malformed",
  "http-reset",
  "http-timeout",
  "decompression-error",
]);

function budgetDetails(
  code: TransportCauseCode,
  policy: TransportPolicy,
): Readonly<Record<string, number>> | undefined {
  if (code === "response-too-large") return { maxResponseBytes: policy.maxResponseBytes };
  if (code === "decompressed-response-too-large") {
    return { maxDecompressedBytes: policy.maxDecompressedBytes };
  }
  return undefined;
}
