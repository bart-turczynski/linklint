/**
 * What `NodeDnsResolverOptions.timeoutMs` actually buys the caller (LINK-vlwzmjki).
 *
 * The option reads as a wall-clock bound on a lookup. It is not one: c-ares
 * treats it as a PER-ATTEMPT value, floors it, doubles it on each retry round,
 * and retries `tries` times. Nothing in this repository could contradict the
 * JSDoc, because the constructed `Resolver` options were observed by no test.
 * The JSDoc now states a worst case of `15 * max(250, timeoutMs)`; these are the
 * assertions that redden if either factor in it stops being true.
 *
 * Two pins, deliberately of different kinds:
 *
 *  - the OPTIONS this port hands to `Resolver`, recorded through a subclass that
 *    still runs the real thing, so the prose about `timeout`/`tries` reddens when
 *    the construction stops matching it; and
 *  - a PREMISE pin against a loopback blackhole — a UDP socket that swallows
 *    every query and answers nothing — for the two c-ares behaviours the prose
 *    quotes numbers for: the retry count and the ~250 ms per-attempt floor. It
 *    uses no external network and no name a real resolver would answer, matching
 *    the discipline in `dns-node-live.test.ts`.
 *
 * The blackhole assertions are a floor and a count, never a ceiling: a loaded
 * machine can only make the query slower, so neither can flake under CPU
 * contention.
 */
import { createSocket, type Socket } from "node:dgram";
import { afterEach, describe, expect, it, vi } from "vitest";

const { constructions } = vi.hoisted(() => ({ constructions: [] as unknown[][] }));

vi.mock("node:dns/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns/promises")>();
  class RecordingResolver extends actual.Resolver {
    constructor(...args: ConstructorParameters<typeof actual.Resolver>) {
      constructions.push(args);
      super(...args);
    }
  }
  return { ...actual, Resolver: RecordingResolver };
});

import {
  createNodeDnsResolver,
  type NodeDnsResolverOptions,
} from "../src/reputation/dns-node.js";

const sockets: Socket[] = [];

afterEach(async () => {
  constructions.length = 0;
  const running = sockets.splice(0, sockets.length);
  await Promise.all(
    running.map(async (s) => new Promise<void>((resolve) => s.close(() => resolve()))),
  );
});

/** Options the port handed to the single `Resolver` it built for one query. */
function soleConstruction(): unknown[] {
  expect(constructions).toHaveLength(1);
  return constructions[0]!;
}

/**
 * A UDP server that receives DNS queries and never answers one, so every attempt
 * runs to its c-ares timeout. Returns its port and a live count of packets seen.
 */
async function startBlackhole(): Promise<{ port: number; received: () => number }> {
  const created = createSocket("udp4");
  sockets.push(created);
  let count = 0;
  created.on("message", () => {
    count += 1;
  });
  await new Promise<void>((resolve) => created.bind(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (typeof address === "string") throw new Error("no port");
  return { port: address.port, received: () => count };
}

/**
 * Drive one query at the blackhole and cancel it the instant it is in flight, so
 * the construction is recorded without waiting out a single c-ares attempt. The
 * abort listener is attached synchronously inside `query`, before the first
 * `await`, so the cancellation always lands.
 */
async function constructedFor(options: NodeDnsResolverOptions): Promise<unknown[]> {
  const { port } = await startBlackhole();
  const controller = new AbortController();
  const pending = createNodeDnsResolver({ ...options, servers: [`127.0.0.1:${port}`] }).query({
    name: "probe.example",
    type: "A",
    signal: controller.signal,
  });
  controller.abort();
  expect((await pending).state).toBe("aborted");
  return soleConstruction();
}

describe("createNodeDnsResolver resolver construction", () => {
  it("builds no resolver at all for a name it rejects locally", async () => {
    await createNodeDnsResolver({ timeoutMs: 200, servers: ["127.0.0.1:0"] }).query({
      name: "",
      type: "A",
    });

    // An empty name short-circuits before any resolver is built, so nothing was
    // recorded; the construction pin needs a query that reaches c-ares.
    expect(constructions).toHaveLength(0);
  });

  it("records the caller's timeout and this port's own attempt count", async () => {
    // The JSDoc's worst case is a multiple of `tries`, so `tries` has to be ours:
    // unset, the multiplier belonged to whichever c-ares the runtime bundled.
    expect(await constructedFor({ timeoutMs: 200 })).toEqual([{ timeout: 200, tries: 4 }]);
  });

  it("still states the attempt count when no timeout is configured", async () => {
    expect(await constructedFor({})).toEqual([{ tries: 4 }]);
  });

  it("treats a non-positive timeout as no timeout at all", async () => {
    expect(await constructedFor({ timeoutMs: 0 })).toEqual([{ tries: 4 }]);
    constructions.length = 0;
    expect(await constructedFor({ timeoutMs: -5 })).toEqual([{ tries: 4 }]);
  });
});

describe("what a silent server costs (c-ares premise)", () => {
  it(
    "spends several attempts and far more than the requested timeout",
    { timeout: 30_000 },
    async () => {
      const { port, received } = await startBlackhole();
      const started = Date.now();
      const answer = await createNodeDnsResolver({
        timeoutMs: 1,
        servers: [`127.0.0.1:${port}`],
      }).query({ name: "probe.example", type: "A" });
      const elapsedMs = Date.now() - started;

      expect(answer.state).toBe("timeout");

      // The floor. A 1 ms request cannot buy a 1 ms attempt: c-ares holds each
      // attempt open for ~250 ms, so ONE attempt alone already overruns the
      // number the caller passed by more than two orders of magnitude.
      expect(elapsedMs).toBeGreaterThanOrEqual(240);

      // The attempt count the documented worst case is a multiple of, observed
      // on the wire rather than taken from the option we set.
      expect(received()).toBe(4);
    },
  );
});
