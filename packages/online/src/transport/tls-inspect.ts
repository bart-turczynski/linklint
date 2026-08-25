/**
 * Observational TLS inspector over the safe pinned transport (LINK-fgdawgnj, M7a).
 *
 * `inspect()` reuses the exact SSRF/DNS-pinning decision the fetch path uses
 * ({@link pinDestination}), connects to the pinned address with original-host SNI,
 * captures the presented certificate WITHOUT sending any HTTP application data, and
 * normalizes it into non-authoritative evidence. It follows no redirects and never
 * converts an observation into permission to connect or fetch anywhere.
 *
 * Outcome discipline:
 * - `blocked` is reserved for transport-policy refusal (a prohibited pinned address);
 * - handshake, DNS, connection, certificate-analysis, timeout, and cancellation
 *   failures are `incomplete` with a typed cause;
 * - a completed `observed` outcome records defects (expired, mismatch, untrusted,
 *   ...) as evidence and is explicitly NOT a claim that a fetch would be allowed.
 */

import { addressesEqual } from "./address.js";
import { isTlsObservationCauseCode } from "./outcome-registry.js";
import { normalizeTlsCertificate, TlsCertificateAnalysisError } from "./tls-certificate.js";
import { pinDestination } from "./pin.js";
import type { ClockPort, ResolverPort } from "./types.js";
import type {
  SafeTlsInspector,
  TlsInspectionPolicy,
  TlsInspectRequest,
  TlsObservationBlocked,
  TlsObservationCause,
  TlsObservationEvidence,
  TlsObservationIncomplete,
  TlsObservationOutcome,
  TlsObservationPort,
  TlsObserved,
} from "./tls-types.js";

export interface CreateSafeTlsInspectorOptions {
  readonly resolver: ResolverPort;
  readonly observer: TlsObservationPort;
  readonly clock: ClockPort;
  readonly policy?: Partial<TlsInspectionPolicy>;
}

interface InspectState {
  subject: string;
  hostname?: string;
  port?: number;
  resolvedAddresses?: readonly string[];
  selectedAddress?: string;
}

type ObservePhase = "dns" | "connect" | "tls";

class ObserveError extends Error {
  constructor(
    readonly phase: ObservePhase,
    readonly original: unknown,
  ) {
    super("tls observation failed");
  }
}

class DeadlineError extends Error {}

export function createSafeTlsInspector(
  options: CreateSafeTlsInspectorOptions,
): SafeTlsInspector {
  return new SafeTlsInspectorImpl(options);
}

class SafeTlsInspectorImpl implements SafeTlsInspector {
  constructor(private readonly options: CreateSafeTlsInspectorOptions) {}

  async inspect(request: TlsInspectRequest): Promise<TlsObservationOutcome> {
    const state: InspectState = { subject: request.url };
    if (request.signal?.aborted) return this.incomplete(state, "caller-aborted");

    const operationController = new AbortController();
    const timerController = new AbortController();
    let timedOut = false;
    const onCallerAbort = () => operationController.abort();
    request.signal?.addEventListener("abort", onCallerAbort, { once: true });

    const work = this.execute(request, state, operationController.signal);
    const deadline = this.options.clock
      .sleep(this.resolvedTimeoutMs(), timerController.signal)
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
      if (error instanceof ObserveError) return this.incomplete(state, observeCause(error));
      if (error instanceof TlsCertificateAnalysisError) {
        return this.incomplete(state, error.code);
      }
      return this.incomplete(state, "tls-handshake");
    } finally {
      timerController.abort();
      request.signal?.removeEventListener("abort", onCallerAbort);
      void work.catch(() => undefined);
      void deadline.catch(() => undefined);
    }
  }

  private async execute(
    request: TlsInspectRequest,
    state: InspectState,
    signal: AbortSignal,
  ): Promise<TlsObservationOutcome> {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return this.incomplete(state, "invalid-url");
    }
    if (url.protocol !== "https:") {
      return this.incomplete(state, "unsupported-scheme", { scheme: url.protocol });
    }
    if (url.username !== "" || url.password !== "") {
      return this.incomplete(state, "url-credentials");
    }

    url.hash = "";
    state.subject = url.href;
    state.hostname = unbracket(url.hostname);
    state.port = url.port === "" ? 443 : Number(url.port);

    const pin = await wrapOperation(
      "dns",
      pinDestination(this.options.resolver, state.hostname, signal),
    );
    if (signal.aborted) throw new ObserveError("dns", { code: "dns-timeout" });
    state.resolvedAddresses = pin.resolvedAddresses;
    if (pin.kind === "dns-not-found") throw new ObserveError("dns", { code: "dns-not-found" });
    if (pin.kind === "dns-malformed") throw new ObserveError("dns", { code: "dns-malformed" });
    if (pin.kind === "prohibited") {
      return this.blocked(state, "prohibited-address", {
        address: pin.address,
        category: pin.category,
      });
    }

    const selected = pin.selected;
    state.selectedAddress = selected.address;

    const observation = await wrapOperation(
      "connect",
      this.options.observer.observe({
        hostname: state.hostname,
        address: selected.address,
        port: state.port,
        serverName: state.hostname,
        signal,
      }),
    );
    if (signal.aborted) throw new ObserveError("connect", { code: "connect-timeout" });
    if (
      observation.remotePort !== state.port ||
      !addressesEqual(selected.address, observation.remoteAddress)
    ) {
      throw new ObserveError("connect", { code: "connection-address-mismatch" });
    }

    const normalized = normalizeTlsCertificate(observation, {
      hostname: state.hostname,
      observedAt: this.options.clock.now(),
      ...(this.options.policy !== undefined ? { policy: this.options.policy } : {}),
    });

    return this.observed(state, normalized);
  }

  private resolvedTimeoutMs(): number {
    const configured = this.options.policy?.maxTotalTimeMs;
    if (typeof configured === "number" && Number.isSafeInteger(configured) && configured > 0) {
      return Math.min(configured, 2_147_483_647);
    }
    return 10_000;
  }

  private observed(state: InspectState, observation: TlsObserved["observation"]): TlsObserved {
    const observedAt = this.options.clock.now().toISOString();
    return {
      status: "observed",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      observation,
    };
  }

  private blocked(
    state: InspectState,
    code: TlsObservationCause["code"],
    details?: TlsObservationCause["details"],
  ): TlsObservationBlocked {
    const observedAt = this.options.clock.now().toISOString();
    return {
      status: "blocked",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      cause: details === undefined ? { code } : { code, details },
    };
  }

  private incomplete(
    state: InspectState,
    code: TlsObservationCause["code"],
    details?: TlsObservationCause["details"],
  ): TlsObservationIncomplete {
    const observedAt = this.options.clock.now().toISOString();
    return {
      status: "incomplete",
      subject: { kind: "url", value: state.subject },
      observedAt,
      evidence: evidence(state, observedAt),
      cause: details === undefined ? { code } : { code, details },
    };
  }
}

async function wrapOperation<T>(phase: ObservePhase, promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (error) {
    if (error instanceof ObserveError) throw error;
    throw new ObserveError(phase, error);
  }
}

function evidence(state: InspectState, observedAt: string): TlsObservationEvidence {
  return {
    type: "tls.attempt",
    subject: { kind: "url", value: state.subject },
    observedAt,
    protocol: "https:",
    ...(state.hostname === undefined ? {} : { hostname: state.hostname }),
    ...(state.port === undefined ? {} : { port: state.port }),
    ...(state.resolvedAddresses === undefined
      ? {}
      : { resolvedAddresses: state.resolvedAddresses }),
    ...(state.selectedAddress === undefined ? {} : { selectedAddress: state.selectedAddress }),
  };
}

function observeCause(error: ObserveError): TlsObservationCause["code"] {
  const stable = stableCode(error.original);
  if (stable) return stable;
  if (error.phase === "dns") return "dns-error";
  if (error.phase === "connect") return "connect-error";
  return "tls-handshake";
}

/**
 * The subset of {@link TLS_OBSERVATION_CAUSE_CODES} an adapter may assert
 * directly through `error.code`. Deliberately proper, under the same rule as
 * `STABLE_OPERATION_CODES` in `safe-transport.ts`, and pinned as a subset by
 * `test/transport-outcome-registry.test.ts`.
 */
const STABLE_OBSERVE_CODES = new Set<TlsObservationCause["code"]>([
  "dns-not-found",
  "dns-timeout",
  "dns-malformed",
  "connect-refused",
  "connect-timeout",
  "connection-address-mismatch",
  "tls-handshake",
]);

function stableCode(error: unknown): TlsObservationCause["code"] | null {
  if (typeof error !== "object" || error === null || !("code" in error)) return null;
  const code = error.code;
  if (!isTlsObservationCauseCode(code)) return null;
  return STABLE_OBSERVE_CODES.has(code) ? code : null;
}

function unbracket(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}
