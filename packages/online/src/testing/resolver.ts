import type { ClockPort } from "./clock.js";
import { UnexpectedFixtureCall } from "./errors.js";
import { runFixtureStep, type FixtureStep } from "./script.js";

export interface DnsAddress {
  readonly address: string;
  readonly family: 4 | 6;
  readonly ttlSeconds: number;
}

export interface ResolveRequest {
  readonly hostname: string;
  readonly signal?: AbortSignal;
}

export interface ResolverPort {
  resolve(request: ResolveRequest): Promise<readonly DnsAddress[]>;
}

export interface ResolverFixtureStep extends FixtureStep<readonly DnsAddress[]> {
  readonly hostname: string;
}

export interface ResolverCall {
  readonly hostname: string;
  readonly abortedAtCall: boolean;
}

/** Exact-order DNS script. Repeating a hostname models rebinding/address changes. */
export class FixtureResolver implements ResolverPort {
  readonly calls: ResolverCall[] = [];
  private readonly steps: ResolverFixtureStep[];

  constructor(
    steps: readonly ResolverFixtureStep[],
    private readonly clock: ClockPort,
  ) {
    this.steps = [...steps];
  }

  async resolve(request: ResolveRequest): Promise<readonly DnsAddress[]> {
    this.calls.push({ hostname: request.hostname, abortedAtCall: request.signal?.aborted ?? false });
    const step = this.steps.shift();
    if (!step) throw new UnexpectedFixtureCall("resolver", request.hostname);
    if (step.hostname !== request.hostname) {
      throw new UnexpectedFixtureCall(
        "resolver",
        `expected ${step.hostname}, received ${request.hostname}`,
      );
    }
    const addresses = await runFixtureStep(step, this.clock, request.signal);
    return addresses.map((address) => ({ ...address }));
  }

  get remainingStepCount(): number {
    return this.steps.length;
  }
}
