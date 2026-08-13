/**
 * IANA RDAP bootstrap acquisition (LINK-mkddydzr, sub-unit B).
 *
 * Two suites. The first drives the updater's state machine against a scripted
 * client, the way the URLhaus/PhishTank updater suites do. The second is the
 * live-loopback half — the precedent set by `rdap-node-live.test.ts` — which
 * runs the SAME updater through the real `createNodeRdapHttpClient` against a
 * real socket, because the conditional-refresh validators only prove anything if
 * they actually reach the wire.
 *
 * No `dns.json` is committed anywhere in this repo. Every document below is
 * built inline by the test that needs it; none of it is shipped or shippable.
 */
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";

import {
  createNodeRdapHttpClient,
  DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS,
  IANA_RDAP_BOOTSTRAP_URL,
  RDAP_BOOTSTRAP_SOURCE_ID,
  RDAP_BOOTSTRAP_SOURCE_VERSION,
  resolveRdapBase,
  updateRdapBootstrap,
  type RdapBootstrapSnapshot,
  type RdapBootstrapSnapshotMetadata,
  type RdapBootstrapStore,
  type RdapHttpClient,
  type RdapHttpRequest,
  type RdapHttpResponse,
} from "../src/reputation/index.js";
import type { TransportAddressDecision } from "../src/transport/types.js";

// --- Fixtures ---------------------------------------------------------------

const NOW = "2026-07-24T06:00:00.000Z";

/** A minimal, well-formed RFC 9224 document. Built here, never a shipped file. */
function bootstrapDocument(
  services: [string[], string[]][] = [
    [["com", "net"], ["https://rdap.verisign.example/v1/"]],
    [["org"], ["https://rdap.publicinterest.example/"]],
  ],
): string {
  return JSON.stringify({
    version: "1.0",
    publication: "2026-07-20T00:00:00Z",
    description: "RDAP bootstrap file for Domain Name System registrations",
    services,
  });
}

/** A scripted client that records requests and replays a queue of responses. */
class ScriptedClient implements RdapHttpClient {
  readonly requests: RdapHttpRequest[] = [];
  private readonly queue: RdapHttpResponse[];

  constructor(...responses: RdapHttpResponse[]) {
    this.queue = responses;
  }

  request(request: RdapHttpRequest): Promise<RdapHttpResponse> {
    this.requests.push(request);
    const next = this.queue.shift();
    if (next === undefined) throw new Error("ScriptedClient exhausted");
    return Promise.resolve(next);
  }
}

/** A client that always throws, to exercise the network-error branch. */
class ThrowingClient implements RdapHttpClient {
  constructor(private readonly error: unknown) {}
  request(): Promise<RdapHttpResponse> {
    return Promise.reject(this.error);
  }
}

/** An in-memory caller-owned store. Tracks how many times it was replaced. */
class MemoryStore implements RdapBootstrapStore {
  replaced = 0;
  private snapshot: RdapBootstrapSnapshot | null;

  constructor(initial: RdapBootstrapSnapshot | null = null) {
    this.snapshot = initial;
  }

  readMetadata(): Promise<RdapBootstrapSnapshotMetadata | null> {
    return Promise.resolve(this.snapshot?.metadata ?? null);
  }

  replace(snapshot: RdapBootstrapSnapshot): Promise<void> {
    this.replaced++;
    this.snapshot = snapshot;
    return Promise.resolve();
  }

  current(): RdapBootstrapSnapshot | null {
    return this.snapshot;
  }
}

const clockAt = (iso: string) => ({ now: () => new Date(iso) });

function resp(
  status: number,
  body = "",
  headers: Record<string, string> = {},
): RdapHttpResponse {
  return { status, body, headers };
}

function baseOptions(client: RdapHttpClient, store: RdapBootstrapStore) {
  return { client, store, clock: clockAt(NOW) };
}

/** A stored snapshot observed at `observedAt`, expiring at `expiresAt`. */
function storedSnapshot(overrides: Partial<RdapBootstrapSnapshotMetadata> = {}) {
  const metadata: RdapBootstrapSnapshotMetadata = {
    source: RDAP_BOOTSTRAP_SOURCE_ID,
    version: RDAP_BOOTSTRAP_SOURCE_VERSION,
    etag: '"v1"',
    lastModified: "Mon, 20 Jul 2026 00:00:00 GMT",
    observedAt: "2026-07-24T05:00:00.000Z",
    expiresAt: "2026-07-25T05:00:00.000Z",
    registryVersion: "1.0",
    registryPublication: "2026-07-20T00:00:00Z",
    serviceCount: 2,
    insecureBaseUrlsDropped: 0,
    ...overrides,
  };
  return {
    metadata,
    registry: {
      version: "1.0",
      publication: "2026-07-20T00:00:00Z",
      services: [[["com"], ["https://rdap.verisign.example/v1/"]]] as const,
    },
  } as RdapBootstrapSnapshot;
}

// --- Acquisition state machine ----------------------------------------------

describe("updateRdapBootstrap", () => {
  it("defaults to the IANA endpoint and populates an empty store", async () => {
    const client = new ScriptedClient(
      resp(200, bootstrapDocument(), { ETag: '"abc"', "Last-Modified": "Mon, 20 Jul 2026 00:00:00 GMT" }),
    );
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("updated");
    expect(client.requests[0]?.url).toBe(IANA_RDAP_BOOTSTRAP_URL);
    expect(IANA_RDAP_BOOTSTRAP_URL).toBe("https://data.iana.org/rdap/dns.json");
    // A first fetch has nothing to condition on.
    expect(client.requests[0]?.conditional).toBeUndefined();
    expect(store.replaced).toBe(1);

    if (result.status !== "updated") return;
    expect(result.snapshot.metadata).toEqual({
      source: RDAP_BOOTSTRAP_SOURCE_ID,
      version: RDAP_BOOTSTRAP_SOURCE_VERSION,
      etag: '"abc"',
      lastModified: "Mon, 20 Jul 2026 00:00:00 GMT",
      observedAt: NOW,
      // Honest freshness: the default cadence, not an invented one.
      expiresAt: new Date(Date.parse(NOW) + DEFAULT_RDAP_BOOTSTRAP_CADENCE_MS).toISOString(),
      registryVersion: "1.0",
      registryPublication: "2026-07-20T00:00:00Z",
      serviceCount: 2,
      insecureBaseUrlsDropped: 0,
    });
    expect(resolveRdapBase(result.snapshot.registry, "example.com")).toEqual({
      status: "routed",
      baseUrl: "https://rdap.verisign.example/v1/",
      tld: "com",
    });
  });

  it("carries no credential slot: the request is url + conditional only", async () => {
    const client = new ScriptedClient(resp(200, bootstrapDocument()));
    const store = new MemoryStore();

    await updateRdapBootstrap(baseOptions(client, store));

    // IANA authenticates nothing, so there is no `credential` option to pass and
    // nothing on the request that could carry one.
    expect(Object.keys(client.requests[0] ?? {})).toEqual(["url"]);
  });

  // --- Cadence guard (the fair-use gate) ------------------------------------

  it("short-circuits within the cadence without contacting IANA", async () => {
    // Exhausted queue: any request at all would throw.
    const client = new ScriptedClient();
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-24T05:00:00.000Z" }));

    const result = await updateRdapBootstrap({
      ...baseOptions(client, store),
      cadenceMs: 7_200_000,
    });

    expect(result).toEqual({
      status: "unchanged",
      metadata: store.current()?.metadata,
      reason: "within-cadence",
    });
    expect(client.requests).toHaveLength(0);
    expect(store.replaced).toBe(0);
  });

  it("applies the fair-use cadence by DEFAULT, unlike the credentialed mirrors", async () => {
    const client = new ScriptedClient();
    // Observed one hour ago; the 24h default covers it with no cadenceMs passed.
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-24T05:00:00.000Z" }));

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("unchanged");
    expect(client.requests).toHaveLength(0);
  });

  it("refreshes once the cadence window has elapsed", async () => {
    const client = new ScriptedClient(resp(200, bootstrapDocument()));
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-20T05:00:00.000Z" }));

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("updated");
    expect(client.requests).toHaveLength(1);
  });

  it("lets a non-positive cadence disable the guard and the expiry deliberately", async () => {
    const client = new ScriptedClient(resp(200, bootstrapDocument()));
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-24T05:59:00.000Z" }));

    const result = await updateRdapBootstrap({
      ...baseOptions(client, store),
      cadenceMs: 0,
    });

    expect(result.status).toBe("updated");
    expect(client.requests).toHaveLength(1);
    if (result.status !== "updated") return;
    // No cadence means no honest expiry to assert.
    expect(result.snapshot.metadata.expiresAt).toBeNull();
  });

  // --- Conditional refresh --------------------------------------------------

  it("echoes the stored validators and treats 304 as unchanged", async () => {
    const client = new ScriptedClient(resp(304));
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-20T05:00:00.000Z" }));

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(client.requests[0]?.conditional).toEqual({
      ifNoneMatch: '"v1"',
      ifModifiedSince: "Mon, 20 Jul 2026 00:00:00 GMT",
    });
    expect(result).toEqual({
      status: "unchanged",
      metadata: store.current()?.metadata,
      reason: "not-modified",
    });
    expect(store.replaced).toBe(0);
  });

  it("treats a 304 with no stored snapshot as a contract violation", async () => {
    const client = new ScriptedClient(resp(304));
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-http-error");
    expect(result.cause.message).toContain("304");
    expect(store.replaced).toBe(0);
  });

  // --- Degradation ----------------------------------------------------------

  it("reports a 429 as a retryable skip carrying Retry-After", async () => {
    const client = new ScriptedClient(resp(429, "", { "Retry-After": "3600" }));
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("skipped");
    if (result.status !== "skipped") return;
    expect(result.cause.code).toBe("rdap-bootstrap-throttled");
    expect(result.cause.retryable).toBe(true);
    expect(result.cause.details).toEqual({ retryAfter: "3600" });
    expect(store.replaced).toBe(0);
  });

  it("reports a non-2xx status as a failure carrying the status", async () => {
    const client = new ScriptedClient(resp(503, "upstream down"));
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-http-error");
    expect(result.cause.details).toEqual({ status: 503 });
  });

  it("reports a transport failure as a network error with its typed code", async () => {
    const error = Object.assign(new Error("boom"), {
      name: "RdapHttpFailure",
      code: "connect-refused",
    });
    const store = new MemoryStore(storedSnapshot({ observedAt: "2026-07-20T05:00:00.000Z" }));

    const result = await updateRdapBootstrap(baseOptions(new ThrowingClient(error), store));

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-network-error");
    expect(result.cause.details).toEqual({ transport: "connect-refused" });
    expect(store.replaced).toBe(0);
  });

  it("reports a pre-start abort as a cancellation skip, with no request", async () => {
    const controller = new AbortController();
    controller.abort();
    const client = new ScriptedClient();

    const result = await updateRdapBootstrap({
      ...baseOptions(client, new MemoryStore()),
      signal: controller.signal,
    });

    expect(result.status).toBe("skipped");
    if (result.status !== "skipped") return;
    expect(result.cause.code).toBe("rdap-bootstrap-caller-aborted");
    expect(client.requests).toHaveLength(0);
  });

  it("reports an in-flight abort as a cancellation skip, not a network failure", async () => {
    const abort = Object.assign(new Error("aborted"), { name: "AbortError" });

    const result = await updateRdapBootstrap(
      baseOptions(new ThrowingClient(abort), new MemoryStore()),
    );

    expect(result.status).toBe("skipped");
    if (result.status !== "skipped") return;
    expect(result.cause.code).toBe("rdap-bootstrap-caller-aborted");
  });

  // --- Parse before write ---------------------------------------------------

  it("does NOT overwrite a good snapshot with a malformed document", async () => {
    const good = storedSnapshot({ observedAt: "2026-07-20T05:00:00.000Z" });
    const store = new MemoryStore(good);
    const client = new ScriptedClient(resp(200, "<html>503 Service Unavailable</html>"));

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-malformed");
    expect(store.replaced).toBe(0);
    expect(store.current()).toBe(good);
  });

  it("rejects valid JSON that is not a valid RFC 9224 registry", async () => {
    const store = new MemoryStore();
    const client = new ScriptedClient(
      resp(200, JSON.stringify({ version: "1.0", services: [["com"]] })),
    );

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-malformed");
    expect(store.replaced).toBe(0);
  });

  // --- Scheme policy --------------------------------------------------------

  it("refuses a non-HTTPS bootstrap URL before contacting anything", async () => {
    const client = new ScriptedClient();

    const result = await updateRdapBootstrap({
      ...baseOptions(client, new MemoryStore()),
      bootstrapUrl: "http://data.iana.example/rdap/dns.json",
    });

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-insecure-url");
    expect(result.cause.details).toEqual({ scheme: "http:" });
    expect(client.requests).toHaveLength(0);
  });

  it("refuses a non-HTTP scheme even under the insecure override", async () => {
    const client = new ScriptedClient();

    const result = await updateRdapBootstrap({
      ...baseOptions(client, new MemoryStore()),
      bootstrapUrl: "file:///etc/rdap/dns.json",
      allowInsecureBootstrapUrl: true,
    });

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-insecure-url");
    expect(client.requests).toHaveLength(0);
  });

  it("refuses a bootstrap URL that is not absolute", async () => {
    const client = new ScriptedClient();

    const result = await updateRdapBootstrap({
      ...baseOptions(client, new MemoryStore()),
      bootstrapUrl: "/rdap/dns.json",
    });

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-insecure-url");
    expect(client.requests).toHaveLength(0);
  });

  it("drops cleartext base URLs, leaving an http-only TLD explicitly unsupported", async () => {
    const client = new ScriptedClient(
      resp(
        200,
        bootstrapDocument([
          [["com"], ["http://rdap.legacy.example/", "https://rdap.verisign.example/v1/"]],
          [["cleartext"], ["http://rdap.cleartext.example/"]],
        ]),
      ),
    );
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("updated");
    if (result.status !== "updated") return;
    const { registry, metadata } = result.snapshot;

    // The mixed entry keeps only its HTTPS base URL...
    expect(resolveRdapBase(registry, "example.com")).toEqual({
      status: "routed",
      baseUrl: "https://rdap.verisign.example/v1/",
      tld: "com",
    });
    // ...and the http-only TLD becomes the explicit unsupported state rather
    // than a cleartext query.
    expect(resolveRdapBase(registry, "example.cleartext")).toEqual({
      status: "unsupported-tld",
      tld: "cleartext",
    });
    expect(registry.services).toHaveLength(1);
    // The trade is recorded, not silent.
    expect(metadata.insecureBaseUrlsDropped).toBe(2);
    expect(metadata.serviceCount).toBe(1);
    expect(JSON.stringify(registry)).not.toContain("http://");
  });

  it("keeps cleartext base URLs only under the explicit opt-in", async () => {
    const client = new ScriptedClient(
      resp(200, bootstrapDocument([[["cleartext"], ["http://rdap.cleartext.example/"]]])),
    );

    const result = await updateRdapBootstrap({
      ...baseOptions(client, new MemoryStore()),
      allowInsecureRdapBases: true,
    });

    expect(result.status).toBe("updated");
    if (result.status !== "updated") return;
    expect(resolveRdapBase(result.snapshot.registry, "example.cleartext")).toEqual({
      status: "routed",
      baseUrl: "http://rdap.cleartext.example/",
      tld: "cleartext",
    });
    expect(result.snapshot.metadata.insecureBaseUrlsDropped).toBe(0);
  });

  it("produces a JSON-safe snapshot the caller can persist as-is", async () => {
    const client = new ScriptedClient(resp(200, bootstrapDocument()));
    const store = new MemoryStore();

    const result = await updateRdapBootstrap(baseOptions(client, store));

    expect(result.status).toBe("updated");
    if (result.status !== "updated") return;
    const roundTripped = JSON.parse(JSON.stringify(result.snapshot)) as RdapBootstrapSnapshot;
    expect(roundTripped).toEqual(result.snapshot);
  });
});

// --- Live loopback ----------------------------------------------------------

let server: Server | undefined;

afterEach(async () => {
  const running = server;
  server = undefined;
  if (running === undefined) return;
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

/** The test seam, as in `rdap-node-live.test.ts`: the shipped policy refuses loopback. */
function allowLoopback(address: string): TransportAddressDecision {
  return { address, family: address.includes(":") ? 6 : 4, allowed: true, category: null };
}

interface Recorded {
  readonly headers: Record<string, string | string[] | undefined>;
}

async function startBootstrapServer(
  handler: (recorded: Recorded) => { status: number; headers?: Record<string, string>; body?: string },
): Promise<number> {
  const created = createServer((req, res) => {
    const reply = handler({ headers: req.headers });
    res.writeHead(reply.status, reply.headers ?? {});
    res.end(reply.body ?? "");
  });
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

describe("updateRdapBootstrap over the real Node client (live loopback)", () => {
  it("downloads, parses and stores a registry, then answers 304 from the echoed validators", async () => {
    const seen: Record<string, string | string[] | undefined>[] = [];
    const port = await startBootstrapServer(({ headers }) => {
      seen.push(headers);
      if (headers["if-none-match"] === '"live-1"') return { status: 304 };
      return {
        status: 200,
        headers: { etag: '"live-1"', "content-type": "application/json" },
        body: bootstrapDocument(),
      };
    });

    const store = new MemoryStore();
    const options = {
      client: createNodeRdapHttpClient({ classifyAddress: allowLoopback }),
      store,
      clock: clockAt(NOW),
      bootstrapUrl: `http://127.0.0.1:${port}/rdap/dns.json`,
      // Loopback cannot serve HTTPS here; the override is the documented seam.
      allowInsecureBootstrapUrl: true,
      cadenceMs: 3_600_000,
    };

    const first = await updateRdapBootstrap(options);
    expect(first.status).toBe("updated");
    expect(store.replaced).toBe(1);
    if (first.status !== "updated") return;
    expect(first.snapshot.metadata.etag).toBe('"live-1"');
    expect(resolveRdapBase(first.snapshot.registry, "example.org").status).toBe("routed");
    // Real wire, real absence: no credential header of any kind was sent.
    expect(seen[0]?.authorization).toBeUndefined();
    expect(seen[0]?.cookie).toBeUndefined();
    expect(seen[0]?.["if-none-match"]).toBeUndefined();

    // A second run outside the cadence must actually put `If-None-Match` on the
    // wire — the whole point of storing the validator.
    const second = await updateRdapBootstrap({
      ...options,
      clock: clockAt("2026-07-25T06:00:00.000Z"),
    });
    expect(second.status).toBe("unchanged");
    if (second.status !== "unchanged") return;
    expect(second.reason).toBe("not-modified");
    expect(seen[1]?.["if-none-match"]).toBe('"live-1"');
    expect(store.replaced).toBe(1);
  });

  it("leaves the stored snapshot intact when the live endpoint serves garbage", async () => {
    const port = await startBootstrapServer(() => ({
      status: 200,
      headers: { "content-type": "text/html" },
      body: "<html><body>Bad Gateway</body></html>",
    }));

    const good = storedSnapshot({ observedAt: "2026-07-20T05:00:00.000Z" });
    const store = new MemoryStore(good);

    const result = await updateRdapBootstrap({
      client: createNodeRdapHttpClient({ classifyAddress: allowLoopback }),
      store,
      clock: clockAt(NOW),
      bootstrapUrl: `http://127.0.0.1:${port}/rdap/dns.json`,
      allowInsecureBootstrapUrl: true,
    });

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-malformed");
    expect(store.current()).toBe(good);
  });

  it("refuses a cleartext endpoint under the DEFAULT scheme policy, before connecting", async () => {
    // The control for the seam used above: without the override, the updater
    // never opens a socket to a cleartext bootstrap endpoint.
    let reached = false;
    const port = await startBootstrapServer(() => {
      reached = true;
      return { status: 200, body: bootstrapDocument() };
    });

    const result = await updateRdapBootstrap({
      client: createNodeRdapHttpClient({ classifyAddress: allowLoopback }),
      store: new MemoryStore(),
      clock: clockAt(NOW),
      bootstrapUrl: `http://127.0.0.1:${port}/rdap/dns.json`,
    });

    expect(result.status).toBe("failure");
    if (result.status !== "failure") return;
    expect(result.cause.code).toBe("rdap-bootstrap-insecure-url");
    expect(reached).toBe(false);
  });
});
