/**
 * Behavioral pin for the outbound EFFECTIVE PORT at every site that derives one
 * (LINK-fnonqivj).
 *
 * The same "explicit `url.port`, else the scheme default" expression is written
 * out at four separate outbound boundaries — L0's fetch, L0's TLS inspection,
 * the RDAP provider client and the mirror-download engine — plus a fifth,
 * string-valued, scheme-default rule inside the feed URL canonicalizer. Before
 * those are consolidated onto one helper, this file records what each site does
 * TODAY, so the consolidation is provably a rename and not a behavior change.
 *
 * It also pins the STRING/NUMBER split deliberately: `mirrors/url-canonical.ts`
 * answers "may this port be omitted from the canonical text", never "what port
 * do we dial", and its result never reaches a socket.
 *
 * WHY THE PROVIDER CLIENTS ARE READ THROUGH A MOCKED `request`. The other
 * provider tests here drive a real loopback server, which can only ever bind an
 * EPHEMERAL port — so it exercises the explicit-port branch and can never
 * exercise the scheme-default branch, whose targets (80 and 443) are privileged
 * and unbindable in a hermetic test. Replacing only `http.request` /
 * `https.request` reads the port option the client computed, which is the value
 * under test, without opening a socket at all. The real socket, header, decode
 * and address-gate wiring stays covered by `rdap-node-live.test.ts` and
 * `mirrors-node-live.test.ts`.
 */
import { describe, expect, it, vi } from "vitest";

const captured = vi.hoisted(() => ({ ports: [] as unknown[] }));

function capturingRequest(options: unknown): never {
  captured.ports.push((options as { port?: unknown }).port);
  throw new Error("effective-port pin: request captured, no socket opened");
}

vi.mock("node:http", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:http")>();
  return { ...actual, request: capturingRequest };
});

vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  return { ...actual, request: capturingRequest };
});

const { createSafeTlsInspector, createSafeTransport } = await import(
  "../src/transport/index.js"
);
const { TransportFixtureHarness } = await import("../src/testing/index.js");
const { createNodeRdapHttpClient } = await import("../src/reputation/rdap-node.js");
const { createNodeMirrorHttpClient } = await import("../src/mirrors/mirror-http-node.js");
const { canonicalizeUrl } = await import("../src/mirrors/url-canonical.js");
const { handshake } = await import("./fixtures/tls-certificates.js");

const PUBLIC_A = "93.184.216.34";

/**
 * Drive one L0 fetch against a fixture scripted for `port`, and report the port
 * L0 actually dialled. `port` is the caller's EXPECTATION and is never
 * re-derived here — a helper that recomputed it would only be testing itself.
 */
async function fetchPort(
  url: string,
  port: number,
): Promise<{ connected: number; evidence: number }> {
  const target = new URL(url);
  const secure = target.protocol === "https:";
  const harness = new TransportFixtureHarness({
    startTime: "2026-07-17T12:00:00.000Z",
    resolver: [
      {
        hostname: "origin.example",
        outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 60 }] },
      },
    ],
    connector: [
      {
        expect: {
          protocol: target.protocol as "http:" | "https:",
          hostname: "origin.example",
          address: PUBLIC_A,
          port,
          ...(secure ? { serverName: "origin.example" } : {}),
        },
        outcome: {
          value: {
            id: "c1",
            protocol: target.protocol as "http:" | "https:",
            remoteAddress: PUBLIC_A,
            remotePort: port,
            ...(secure
              ? {
                  tls: {
                    authorized: true,
                    serverName: "origin.example",
                    peerDnsNames: ["origin.example"],
                  },
                }
              : {}),
          },
        },
      },
    ],
    http: [
      {
        expect: { connectionId: "c1", url: target.href, method: "GET" },
        outcome: { value: { status: 200, body: "ok" } },
      },
    ],
  });
  const session = createSafeTransport({
    resolver: harness.resolver,
    connector: harness.connector,
    http: harness.http,
    clock: harness.clock,
  }).createSession();

  const outcome = await session.fetch({
    url,
    authorization: { kind: "destination-fetch", url },
  });
  expect(outcome.status).toBe("success");
  const connected = harness.connector.calls[0]?.port;
  expect(typeof connected).toBe("number");
  return { connected: connected as number, evidence: outcome.evidence.port as number };
}

/** Drive one L0 TLS inspection scripted for `port`, and report the port it dialled. */
async function inspectPort(
  url: string,
  port: number,
): Promise<{ observed: number; evidence: number }> {
  const harness = new TransportFixtureHarness({
    startTime: "2026-01-01T00:00:00.000Z",
    resolver: [
      {
        hostname: "example.com",
        outcome: { value: [{ address: PUBLIC_A, family: 4, ttlSeconds: 60 }] },
      },
    ],
    tlsObserver: [
      {
        expect: {
          hostname: "example.com",
          address: PUBLIC_A,
          port,
          serverName: "example.com",
        },
        outcome: { value: handshake("valid", { remotePort: port }) },
      },
    ],
  });
  const outcome = await createSafeTlsInspector({
    resolver: harness.resolver,
    observer: harness.tlsObserver,
    clock: harness.clock,
  }).inspect({ url });
  expect(outcome.status).toBe("observed");
  const observed = harness.tlsObserver.calls[0]?.port;
  expect(typeof observed).toBe("number");
  return { observed: observed as number, evidence: outcome.evidence.port as number };
}

/** Read the port the RDAP client would have dialled, without dialling it. */
async function rdapPort(url: string): Promise<unknown> {
  captured.ports.length = 0;
  const client = createNodeRdapHttpClient();
  await client.request({ url }).then(
    () => undefined,
    () => undefined,
  );
  expect(captured.ports).toHaveLength(1);
  return captured.ports[0];
}

/** Read the port the mirror-download engine would have dialled. */
async function mirrorPort(url: string): Promise<unknown> {
  captured.ports.length = 0;
  const send = createNodeMirrorHttpClient(
    {
      failure: (code: string) => new Error(code),
      abort: () => new Error("aborted"),
    },
    { allowInsecureUrl: true },
  );
  await send({ url, headers: {} }).then(
    () => undefined,
    () => undefined,
  );
  expect(captured.ports).toHaveLength(1);
  return captured.ports[0];
}

describe("effective port — L0 fetch (transport/safe-transport.ts)", () => {
  it("defaults an https destination without a port to 443", async () => {
    expect(await fetchPort("https://origin.example/start", 443)).toEqual({
      connected: 443,
      evidence: 443,
    });
  });

  it("defaults an http destination without a port to 80", async () => {
    expect(await fetchPort("http://origin.example/start", 80)).toEqual({
      connected: 80,
      evidence: 80,
    });
  });

  it("uses an explicit port on either scheme", async () => {
    expect(await fetchPort("https://origin.example:8443/start", 8443)).toEqual({
      connected: 8443,
      evidence: 8443,
    });
    expect(await fetchPort("http://origin.example:8080/start", 8080)).toEqual({
      connected: 8080,
      evidence: 8080,
    });
  });

  it("treats a redundantly written default port as the default", async () => {
    // WHATWG `URL` erases `:443` on https, so this arrives at the derivation as
    // the empty-port case and must still dial 443.
    expect(new URL("https://origin.example:443/start").port).toBe("");
    expect(await fetchPort("https://origin.example:443/start", 443)).toEqual({
      connected: 443,
      evidence: 443,
    });
  });

  it("treats the other scheme's default as an explicit port", async () => {
    expect(await fetchPort("https://origin.example:80/start", 80)).toEqual({
      connected: 80,
      evidence: 80,
    });
  });
});

describe("effective port — L0 TLS inspection (transport/tls-inspect.ts)", () => {
  it("defaults to 443 when the URL carries no port", async () => {
    expect(await inspectPort("https://example.com/login", 443)).toEqual({
      observed: 443,
      evidence: 443,
    });
  });

  it("uses an explicit port", async () => {
    expect(await inspectPort("https://example.com:8443/login", 8443)).toEqual({
      observed: 8443,
      evidence: 8443,
    });
  });

  it("treats a redundantly written :443 as the default", async () => {
    expect(await inspectPort("https://example.com:443/login", 443)).toEqual({
      observed: 443,
      evidence: 443,
    });
  });
});

describe("effective port — RDAP provider client (reputation/rdap-node.ts)", () => {
  it("defaults by scheme when the URL carries no port", async () => {
    expect(await rdapPort("https://rdap.example/domain/x")).toBe(443);
    expect(await rdapPort("http://rdap.example/domain/x")).toBe(80);
  });

  it("uses an explicit port, as a number", async () => {
    expect(await rdapPort("https://rdap.example:8443/domain/x")).toBe(8443);
    expect(await rdapPort("http://rdap.example:8080/domain/x")).toBe(8080);
  });

  it("treats the other scheme's default as an explicit port", async () => {
    expect(await rdapPort("https://rdap.example:80/domain/x")).toBe(80);
    expect(await rdapPort("http://rdap.example:443/domain/x")).toBe(443);
  });
});

describe("effective port — mirror download engine (mirrors/mirror-http-node.ts)", () => {
  it("defaults by scheme when the URL carries no port", async () => {
    expect(await mirrorPort("https://feed.example/dump.csv")).toBe(443);
    expect(await mirrorPort("http://feed.example/dump.csv")).toBe(80);
  });

  it("uses an explicit port, as a number", async () => {
    expect(await mirrorPort("https://feed.example:8443/dump.csv")).toBe(8443);
    expect(await mirrorPort("http://feed.example:8080/dump.csv")).toBe(8080);
  });

  it("treats the other scheme's default as an explicit port", async () => {
    expect(await mirrorPort("https://feed.example:80/dump.csv")).toBe(80);
    expect(await mirrorPort("http://feed.example:443/dump.csv")).toBe(443);
  });
});

describe("default port — feed URL canonicalizer (mirrors/url-canonical.ts)", () => {
  /**
   * A DIFFERENT question, pinned here so the difference is visible: this site
   * decides whether a port may be OMITTED from canonical TEXT. It compares
   * against a string, its answer is never a dial target, and no branch of it
   * ever yields a number.
   */
  it("omits the scheme's default port from the canonical text", () => {
    // WHATWG `URL` has already erased the default port before the comparison
    // runs, so the empty-port arm is what actually carries these cases.
    expect(new URL("https://feed.example:443/a").port).toBe("");
    expect(new URL("http://feed.example:80/a").port).toBe("");
    expect(canonicalizeUrl("https://Feed.Example:443/a?b=1")).toBe(
      "https://feed.example/a?b=1",
    );
    expect(canonicalizeUrl("http://Feed.Example:80/a?b=1")).toBe(
      "http://feed.example/a?b=1",
    );
  });

  it("keeps a non-default port verbatim, including the other scheme's default", () => {
    expect(canonicalizeUrl("https://feed.example:8443/a")).toBe(
      "https://feed.example:8443/a",
    );
    expect(canonicalizeUrl("https://feed.example:80/a")).toBe("https://feed.example:80/a");
    expect(canonicalizeUrl("http://feed.example:443/a")).toBe("http://feed.example:443/a");
  });

  it("emits no port at all when the URL carried none", () => {
    expect(canonicalizeUrl("https://feed.example/a")).toBe("https://feed.example/a");
    expect(canonicalizeUrl("http://feed.example/a")).toBe("http://feed.example/a");
  });
});
