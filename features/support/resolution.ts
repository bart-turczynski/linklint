import { createSafeTransport } from "../../packages/online/src/transport/index.js";
import {
  TransportFixtureHarness,
  type FixtureConnection,
  type TransportFixtureScript,
} from "../../packages/online/src/testing/index.js";

/**
 * Cucumber support helpers for the Layer 2 (online resolution) acceptance
 * matrix. This module only CONSTRUCTS the deterministic fixture transport,
 * mirroring `packages/online/test/redirect-chain.test.ts` (`scriptFor` +
 * `connection` + `createSafeTransport`). Assertions live in the step file.
 *
 * Zero real network: every hop is answered by an exact-order DNS + connect +
 * HTTP fixture. The clock is frozen at {@link START_TIME} so `observedAt` is
 * stable.
 */

/** Stable public address every hostname resolves to (unless overridden). */
export const PUBLIC_ADDRESS = "93.184.216.34";
/** Frozen clock instant so enrichment `observedAt` values are deterministic. */
export const START_TIME = "2026-07-17T12:00:00.000Z";
/** Cloud link-local metadata address used by the SSRF safety row. */
export const METADATA_ADDRESS = "169.254.169.254";

/** One scripted transport response, keyed to a single hop URL. */
export interface ResponseStep {
  readonly url: string;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: string;
  readonly method?: "GET" | "HEAD";
}

export interface BuildFixtureOptions {
  /**
   * Resolve specific hostnames to a NON-public address (e.g. cloud metadata)
   * to exercise the SSRF safety row. A hostname listed here is answered by DNS
   * but blocked before connect, so it gets no connector/HTTP fixture step.
   */
  readonly resolveHostTo?: Readonly<Record<string, string>>;
}

function portFor(parsed: URL): number {
  return parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port);
}

function connection(id: string, url: string): FixtureConnection {
  const parsed = new URL(url);
  return {
    id,
    protocol: parsed.protocol as "http:" | "https:",
    remoteAddress: PUBLIC_ADDRESS,
    remotePort: portFor(parsed),
    ...(parsed.protocol === "https:"
      ? {
          tls: {
            authorized: true,
            serverName: parsed.hostname,
            peerDnsNames: [parsed.hostname],
          },
        }
      : {}),
  };
}

function scriptFor(
  steps: readonly ResponseStep[],
  options: BuildFixtureOptions,
): TransportFixtureScript {
  const resolveHostTo = options.resolveHostTo ?? {};
  const isBlocked = (step: ResponseStep): boolean =>
    Object.hasOwn(resolveHostTo, new URL(step.url).hostname);

  // A blocked host is answered by DNS but never connected to, so only
  // reachable steps get connector/HTTP fixtures (kept in exact call order).
  const reachable = steps.filter((step) => !isBlocked(step));

  return {
    startTime: START_TIME,
    resolver: steps.map((step) => {
      const hostname = new URL(step.url).hostname;
      const address = resolveHostTo[hostname] ?? PUBLIC_ADDRESS;
      const family = address.includes(":") ? (6 as const) : (4 as const);
      return {
        hostname,
        outcome: { value: [{ address, family, ttlSeconds: 60 }] },
      };
    }),
    connector: reachable.map((step, index) => {
      const parsed = new URL(step.url);
      return {
        expect: {
          protocol: parsed.protocol as "http:" | "https:",
          hostname: parsed.hostname,
          address: PUBLIC_ADDRESS,
          port: portFor(parsed),
          ...(parsed.protocol === "https:" ? { serverName: parsed.hostname } : {}),
        },
        outcome: { value: connection(`c${index + 1}`, step.url) },
      };
    }),
    http: reachable.map((step, index) => ({
      expect: {
        connectionId: `c${index + 1}`,
        url: step.url,
        method: step.method ?? "GET",
      },
      outcome: {
        value: {
          status: step.status,
          ...(step.headers === undefined ? {} : { headers: step.headers }),
          ...(step.body === undefined ? {} : { body: step.body }),
        },
      },
    })),
  };
}

export interface FixtureTransport {
  readonly harness: TransportFixtureHarness;
  readonly transport: ReturnType<typeof createSafeTransport>;
}

/**
 * Build a deterministic {@link TransportFixtureHarness} + safe transport from a
 * list of hop responses, replicating the canonical construction in
 * `redirect-chain.test.ts`.
 */
export function buildFixtureTransport(
  steps: readonly ResponseStep[],
  options: BuildFixtureOptions = {},
): FixtureTransport {
  const harness = new TransportFixtureHarness(scriptFor(steps, options));
  const transport = createSafeTransport({
    resolver: harness.resolver,
    connector: harness.connector,
    http: harness.http,
    clock: harness.clock,
  });
  return { harness, transport };
}

/** Always-grant exact-URL authorizer, matching the test harness. */
export const allowAll = async ({ url }: { url: string }) => ({
  kind: "destination-fetch" as const,
  url,
});

/** A frozen `now` provider bound to {@link START_TIME} for transport-less enrichers. */
export const frozenNow = () => new Date(START_TIME);

/** Build the exact Microsoft Safe Links standard wrapper for a destination. */
export function microsoftSafeLink(destination: string): string {
  return (
    `https://nam01.safelinks.protection.outlook.com/?url=${encodeURIComponent(destination)}` +
    "&data=05%7C01&reserved=0"
  );
}
