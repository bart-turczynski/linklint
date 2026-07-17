import type { ClockPort } from "./clock.js";
import { UnexpectedFixtureCall } from "./errors.js";
import { runFixtureStep, type FixtureStep } from "./script.js";

export interface ConnectRequest {
  readonly protocol: "http:" | "https:";
  readonly hostname: string;
  readonly address: string;
  readonly port: number;
  readonly serverName?: string;
  readonly signal?: AbortSignal;
}

export interface FixtureConnection {
  readonly id: string;
  readonly protocol: "http:" | "https:";
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly tls?: {
    readonly authorized: boolean;
    readonly serverName: string;
    readonly peerDnsNames: readonly string[];
  };
}

export interface ConnectorPort {
  connect(request: ConnectRequest): Promise<FixtureConnection>;
}

export interface ConnectorExpectation {
  readonly protocol: "http:" | "https:";
  readonly hostname: string;
  readonly address: string;
  readonly port: number;
  readonly serverName?: string;
}

export interface ConnectorFixtureStep extends FixtureStep<FixtureConnection> {
  readonly expect: ConnectorExpectation;
}

export type ConnectorCall = ConnectorExpectation & { readonly abortedAtCall: boolean };

/**
 * Exact-order connection script. The expectation separately pins the selected
 * address and the original hostname/SNI identity.
 */
export class FixtureConnector implements ConnectorPort {
  readonly calls: ConnectorCall[] = [];
  private readonly steps: ConnectorFixtureStep[];

  constructor(
    steps: readonly ConnectorFixtureStep[],
    private readonly clock: ClockPort,
  ) {
    this.steps = [...steps];
  }

  async connect(request: ConnectRequest): Promise<FixtureConnection> {
    const call = connectorCall(request);
    this.calls.push(call);
    const step = this.steps.shift();
    if (!step) throw new UnexpectedFixtureCall("connector", renderCall(call));
    const mismatch = firstMismatch(step.expect, call);
    if (mismatch) throw new UnexpectedFixtureCall("connector", mismatch);
    return runFixtureStep(step, this.clock, request.signal);
  }

  get remainingStepCount(): number {
    return this.steps.length;
  }
}

function connectorCall(request: ConnectRequest): ConnectorCall {
  const base = {
    protocol: request.protocol,
    hostname: request.hostname,
    address: request.address,
    port: request.port,
    abortedAtCall: request.signal?.aborted ?? false,
  } as const;
  return request.serverName === undefined ? base : { ...base, serverName: request.serverName };
}

function firstMismatch(expected: ConnectorExpectation, actual: ConnectorCall): string | null {
  for (const key of ["protocol", "hostname", "address", "port", "serverName"] as const) {
    if (expected[key] !== actual[key]) {
      return `${key}: expected ${String(expected[key])}, received ${String(actual[key])}`;
    }
  }
  return null;
}

function renderCall(call: ConnectorCall): string {
  return `${call.protocol}//${call.hostname}:${call.port} via ${call.address}`;
}
