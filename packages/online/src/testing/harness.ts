import { FixtureClock } from "./clock.js";
import { FixtureConnector, type ConnectorFixtureStep } from "./connector.js";
import { FixtureHttp, type HttpFixtureStep } from "./http.js";
import { FixtureResolver, type ResolverFixtureStep } from "./resolver.js";
import { FixtureTlsObserver, type TlsObserverFixtureStep } from "./tls-observer.js";

export interface TransportFixtureScript {
  readonly startTime?: string | number | Date;
  readonly resolver?: readonly ResolverFixtureStep[];
  readonly connector?: readonly ConnectorFixtureStep[];
  readonly http?: readonly HttpFixtureStep[];
  readonly tlsObserver?: readonly TlsObserverFixtureStep[];
}

/** Coordinated zero-I/O fixture ports with one shared deterministic clock. */
export class TransportFixtureHarness {
  readonly clock: FixtureClock;
  readonly resolver: FixtureResolver;
  readonly connector: FixtureConnector;
  readonly http: FixtureHttp;
  readonly tlsObserver: FixtureTlsObserver;

  constructor(script: TransportFixtureScript = {}) {
    this.clock = new FixtureClock(script.startTime);
    this.resolver = new FixtureResolver(script.resolver ?? [], this.clock);
    this.connector = new FixtureConnector(script.connector ?? [], this.clock);
    this.http = new FixtureHttp(script.http ?? [], this.clock);
    this.tlsObserver = new FixtureTlsObserver(script.tlsObserver ?? [], this.clock);
  }

  assertExhausted(): void {
    const remaining = [
      ["resolver", this.resolver.remainingStepCount],
      ["connector", this.connector.remainingStepCount],
      ["http", this.http.remainingStepCount],
      ["tls-observer", this.tlsObserver.remainingStepCount],
    ] as const;
    const unconsumed = remaining.filter(([, count]) => count > 0);
    if (unconsumed.length > 0) {
      throw new Error(
        `unconsumed fixture steps: ${unconsumed.map(([port, count]) => `${port}=${count}`).join(", ")}`,
      );
    }
  }
}
