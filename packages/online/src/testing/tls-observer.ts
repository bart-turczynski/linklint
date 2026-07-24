import type { ClockPort } from "./clock.js";
import { UnexpectedFixtureCall } from "./errors.js";
import { runFixtureStep, type FixtureStep } from "./script.js";
import type {
  TlsHandshakeObservation,
  TlsObservationPort,
  TlsObserveConnectRequest,
} from "../transport/tls-types.js";

export interface TlsObserveExpectation {
  readonly hostname: string;
  readonly address: string;
  readonly port: number;
  readonly serverName: string;
}

export interface TlsObserverFixtureStep extends FixtureStep<TlsHandshakeObservation> {
  readonly expect: TlsObserveExpectation;
}

export type TlsObserverCall = TlsObserveExpectation & { readonly abortedAtCall: boolean };

/**
 * Exact-order TLS-observation script. The expectation pins the selected address and
 * the original hostname/SNI identity, mirroring the fetch connector fixture.
 */
export class FixtureTlsObserver implements TlsObservationPort {
  readonly calls: TlsObserverCall[] = [];
  private readonly steps: TlsObserverFixtureStep[];

  constructor(
    steps: readonly TlsObserverFixtureStep[],
    private readonly clock: ClockPort,
  ) {
    this.steps = [...steps];
  }

  async observe(request: TlsObserveConnectRequest): Promise<TlsHandshakeObservation> {
    const call: TlsObserverCall = {
      hostname: request.hostname,
      address: request.address,
      port: request.port,
      serverName: request.serverName,
      abortedAtCall: request.signal?.aborted ?? false,
    };
    this.calls.push(call);
    const step = this.steps.shift();
    if (!step) throw new UnexpectedFixtureCall("tls-observer", renderCall(call));
    const mismatch = firstMismatch(step.expect, call);
    if (mismatch) throw new UnexpectedFixtureCall("tls-observer", mismatch);
    return runFixtureStep(step, this.clock, request.signal);
  }

  get remainingStepCount(): number {
    return this.steps.length;
  }
}

function firstMismatch(expected: TlsObserveExpectation, actual: TlsObserverCall): string | null {
  for (const key of ["hostname", "address", "port", "serverName"] as const) {
    if (expected[key] !== actual[key]) {
      return `${key}: expected ${String(expected[key])}, received ${String(actual[key])}`;
    }
  }
  return null;
}

function renderCall(call: TlsObserverCall): string {
  return `tls ${call.hostname}:${call.port} via ${call.address}`;
}
