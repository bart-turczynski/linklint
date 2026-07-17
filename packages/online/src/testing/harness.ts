import { FixtureClock } from "./clock.js";
import { FixtureConnector, type ConnectorFixtureStep } from "./connector.js";
import { FixtureHttp, type HttpFixtureStep } from "./http.js";
import { FixtureResolver, type ResolverFixtureStep } from "./resolver.js";

export interface TransportFixtureScript {
  readonly startTime?: string | number | Date;
  readonly resolver?: readonly ResolverFixtureStep[];
  readonly connector?: readonly ConnectorFixtureStep[];
  readonly http?: readonly HttpFixtureStep[];
}

/** Coordinated zero-I/O fixture ports with one shared deterministic clock. */
export class TransportFixtureHarness {
  readonly clock: FixtureClock;
  readonly resolver: FixtureResolver;
  readonly connector: FixtureConnector;
  readonly http: FixtureHttp;

  constructor(script: TransportFixtureScript = {}) {
    this.clock = new FixtureClock(script.startTime);
    this.resolver = new FixtureResolver(script.resolver ?? [], this.clock);
    this.connector = new FixtureConnector(script.connector ?? [], this.clock);
    this.http = new FixtureHttp(script.http ?? [], this.clock);
  }

  assertExhausted(): void {
    const remaining = [
      ["resolver", this.resolver.remainingStepCount],
      ["connector", this.connector.remainingStepCount],
      ["http", this.http.remainingStepCount],
    ] as const;
    const unconsumed = remaining.filter(([, count]) => count > 0);
    if (unconsumed.length > 0) {
      throw new Error(
        `unconsumed fixture steps: ${unconsumed.map(([port, count]) => `${port}=${count}`).join(", ")}`,
      );
    }
  }
}
