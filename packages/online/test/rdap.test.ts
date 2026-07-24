import { describe, expect, it } from "vitest";

import {
  assertValidSourceDescriptor,
  preflightOnlineSource,
} from "../src/sources/index.js";
import {
  DEFAULT_RDAP_MAX_REDIRECTS,
  fetchRdapDomain,
  normalizeRdapDomain,
  parseRdapBootstrap,
  RDAP_SOURCE_DESCRIPTOR,
  resolveRdapBase,
  type RdapBootstrapRegistry,
  type RdapCache,
  type RdapDomainRecord,
  type RdapHttpClient,
  type RdapHttpResponse,
} from "../src/reputation/index.js";

// --- Fixtures ---------------------------------------------------------------

const registry: RdapBootstrapRegistry = {
  version: "1.0",
  publication: "2026-01-01T00:00:00Z",
  services: [
    [["com", "net"], ["https://rdap.verisign.example/v1"]],
    [["uk"], ["https://rdap.nominet.example/"]],
    [["org"], ["http://rdap-insecure.example/", "https://rdap.publicinterest.example/"]],
  ],
};

const comDomainJson = JSON.stringify({
  objectClassName: "domain",
  ldhName: "example.com",
  status: ["client transfer prohibited"],
  events: [
    { eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" },
    { eventAction: "last changed", eventDate: "2024-08-14T07:01:44Z" },
    { eventAction: "expiration", eventDate: "2025-08-13T04:00:00Z" },
  ],
  entities: [
    {
      objectClassName: "entity",
      roles: ["registrar"],
      handle: "376",
      vcardArray: [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "IANA Registrar"],
        ],
      ],
    },
  ],
  nameservers: [{ ldhName: "a.iana-servers.net" }, { ldhName: "b.iana-servers.net" }],
  secureDNS: { delegationSigned: true },
});

const redactedUkJson = JSON.stringify({
  objectClassName: "domain",
  ldhName: "example.uk",
  events: [{ eventAction: "registration", eventDate: "2010-01-05T00:00:00Z" }],
  entities: [
    { roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar Ltd"]]] },
  ],
  redacted: [{ name: { type: "Registrant Name" } }],
});

function resp(
  status: number,
  body = "",
  headers: Record<string, string> = {},
): RdapHttpResponse {
  return { status, body, headers };
}

/** A scripted, deterministic RDAP client that records the URLs it is asked for. */
class ScriptedRdapClient implements RdapHttpClient {
  readonly requests: string[] = [];
  private readonly steps: (RdapHttpResponse | { throw: Error })[];

  constructor(steps: (RdapHttpResponse | { throw: Error })[]) {
    this.steps = [...steps];
  }

  async request({ url }: { url: string }): Promise<RdapHttpResponse> {
    this.requests.push(url);
    const step = this.steps.shift();
    if (!step) throw new Error(`unexpected RDAP request: ${url}`);
    if ("throw" in step) throw step.throw;
    return step;
  }
}

function memoryCache(): RdapCache {
  const store = new Map<string, RdapDomainRecord>();
  return { get: (key) => store.get(key), set: (key, record) => void store.set(key, record) };
}

function mutableClock(start: string): { now(): Date; advance(ms: number): void } {
  let current = new Date(start);
  return {
    now: () => current,
    advance: (ms) => {
      current = new Date(current.getTime() + ms);
    },
  };
}

// --- Bootstrap routing ------------------------------------------------------

describe("RDAP bootstrap routing", () => {
  it("parses and rejects a malformed registry", () => {
    expect(parseRdapBootstrap(registry)).not.toBeNull();
    expect(parseRdapBootstrap({ version: "1.0" })).toBeNull();
    expect(parseRdapBootstrap({ version: "1", publication: "x", services: [[["com"]]] })).toBeNull();
  });

  it("routes a gTLD and a ccTLD to their authoritative base URLs", () => {
    expect(resolveRdapBase(registry, "example.com")).toEqual({
      status: "routed",
      baseUrl: "https://rdap.verisign.example/v1/",
      tld: "com",
    });
    expect(resolveRdapBase(registry, "example.co.uk")).toMatchObject({
      status: "routed",
      baseUrl: "https://rdap.nominet.example/",
      tld: "uk",
    });
  });

  it("prefers an HTTPS base URL over an insecure one", () => {
    expect(resolveRdapBase(registry, "example.org")).toMatchObject({
      baseUrl: "https://rdap.publicinterest.example/",
    });
  });

  it("reports an unsupported TLD instead of guessing an endpoint", () => {
    expect(resolveRdapBase(registry, "example.zzz")).toEqual({
      status: "unsupported-tld",
      tld: "zzz",
    });
  });
});

// --- Normalization ----------------------------------------------------------

describe("RDAP normalization", () => {
  const ctx = { domain: "example.com", observedAt: "2026-07-24T00:00:00.000Z", expiresAt: null };

  it("extracts events, registrar, nameservers, and secureDNS", () => {
    const record = normalizeRdapDomain(JSON.parse(comDomainJson), ctx);
    expect(record.registrationDate).toBe("1995-08-14T04:00:00.000Z");
    expect(record.lastChangedDate).toBe("2024-08-14T07:01:44.000Z");
    expect(record.expirationDate).toBe("2025-08-13T04:00:00.000Z");
    expect(record.registrar).toEqual({ name: "IANA Registrar", handle: "376" });
    expect(record.nameservers).toEqual(["a.iana-servers.net", "b.iana-servers.net"]);
    expect(record.delegationSigned).toBe(true);
    expect(record.statuses).toEqual(["client transfer prohibited"]);
    expect(record.redacted).toEqual([]);
  });

  it("preserves redacted and absent fields as unknown", () => {
    const record = normalizeRdapDomain(JSON.parse(redactedUkJson), {
      ...ctx,
      domain: "example.uk",
    });
    expect(record.registrationDate).toBe("2010-01-05T00:00:00.000Z");
    expect(record.lastChangedDate).toBeNull();
    expect(record.delegationSigned).toBeNull();
    expect(record.registrar).toEqual({ name: "Example Registrar Ltd", handle: null });
    expect(record.redacted).toEqual(["Registrant Name"]);
  });

  it("returns an all-unknown record for non-object input", () => {
    const record = normalizeRdapDomain("not-json", ctx);
    expect(record.registrationDate).toBeNull();
    expect(record.registrar).toBeNull();
    expect(record.nameservers).toEqual([]);
  });
});

// --- Client lookup ----------------------------------------------------------

describe("fetchRdapDomain", () => {
  const base = () => ({
    registry,
    clock: mutableClock("2026-07-24T00:00:00.000Z"),
  });

  it("fetches and normalizes a live domain, deriving cache freshness", async () => {
    const client = new ScriptedRdapClient([resp(200, comDomainJson)]);
    const result = await fetchRdapDomain({
      ...base(),
      client,
      registrableDomain: "example.com",
      cacheTtlMs: 60_000,
    });
    expect(client.requests).toEqual(["https://rdap.verisign.example/v1/domain/example.com"]);
    expect(result.status).toBe("found");
    if (result.status === "found") {
      expect(result.fromCache).toBe(false);
      expect(result.record.registrationDate).toBe("1995-08-14T04:00:00.000Z");
      expect(result.record.expiresAt).toBe("2026-07-24T00:01:00.000Z");
    }
  });

  it("converts an IDN input to its A-label before querying", async () => {
    const client = new ScriptedRdapClient([resp(200, comDomainJson)]);
    await fetchRdapDomain({ ...base(), client, registrableDomain: "bücher.com" });
    expect(client.requests).toEqual(["https://rdap.verisign.example/v1/domain/xn--bcher-kva.com"]);
  });

  it("treats 404 as a no-hit, never a safety claim", async () => {
    const client = new ScriptedRdapClient([resp(404)]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "gone.com" });
    expect(result).toEqual({ status: "no-hit", domain: "gone.com" });
  });

  it("treats 429 as a retryable throttle skip", async () => {
    const client = new ScriptedRdapClient([resp(429, "", { "retry-after": "120" })]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "busy.com" });
    expect(result.status).toBe("skipped");
    if (result.status === "skipped") {
      expect(result.cause.code).toBe("rdap-throttled");
      expect(result.cause.retryable).toBe(true);
      expect(result.cause.details).toMatchObject({ retryAfter: "120" });
    }
  });

  it("treats a 5xx as a failure and malformed JSON as a failure", async () => {
    const serverError = await fetchRdapDomain({
      ...base(),
      client: new ScriptedRdapClient([resp(503)]),
      registrableDomain: "down.com",
    });
    expect(serverError).toMatchObject({ status: "failure", cause: { code: "rdap-http-error" } });

    const malformed = await fetchRdapDomain({
      ...base(),
      client: new ScriptedRdapClient([resp(200, "{not json")]),
      registrableDomain: "bad.com",
    });
    expect(malformed).toMatchObject({ status: "failure", cause: { code: "rdap-malformed" } });
  });

  it("skips an unsupported TLD before any request", async () => {
    const client = new ScriptedRdapClient([]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "site.zzz" });
    expect(client.requests).toEqual([]);
    expect(result).toMatchObject({ status: "skipped", cause: { code: "rdap-unsupported-tld" } });
  });

  it("follows a bounded RDAP redirect and then normalizes", async () => {
    const client = new ScriptedRdapClient([
      resp(302, "", { location: "https://rdap2.verisign.example/domain/example.net" }),
      resp(200, comDomainJson),
    ]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "example.net" });
    expect(client.requests).toEqual([
      "https://rdap.verisign.example/v1/domain/example.net",
      "https://rdap2.verisign.example/domain/example.net",
    ]);
    expect(result.status).toBe("found");
  });

  it("fails a redirect loop instead of looping forever", async () => {
    const target = "https://rdap.verisign.example/v1/domain/loop.com";
    const client = new ScriptedRdapClient([
      resp(302, "", { location: target }),
      resp(302, "", { location: target }),
    ]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "loop.com" });
    expect(result).toMatchObject({ status: "failure", cause: { code: "rdap-too-many-redirects" } });
  });

  it("maps a client transport error to a network failure", async () => {
    const client = new ScriptedRdapClient([{ throw: new Error("ECONNRESET") }]);
    const result = await fetchRdapDomain({ ...base(), client, registrableDomain: "flaky.com" });
    expect(result).toMatchObject({ status: "failure", cause: { code: "rdap-network-error" } });
  });

  it("skips a pre-aborted lookup as caller-aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const client = new ScriptedRdapClient([]);
    const result = await fetchRdapDomain({
      ...base(),
      client,
      registrableDomain: "example.com",
      signal: controller.signal,
    });
    expect(client.requests).toEqual([]);
    expect(result).toMatchObject({ status: "skipped", cause: { code: "rdap-caller-aborted" } });
  });

  it("serves a fresh cache hit and refetches only after expiry", async () => {
    const clock = mutableClock("2026-07-24T00:00:00.000Z");
    const cache = memoryCache();
    const client = new ScriptedRdapClient([resp(200, comDomainJson), resp(200, comDomainJson)]);

    const first = await fetchRdapDomain({
      registry,
      clock,
      client,
      cache,
      registrableDomain: "example.com",
      cacheTtlMs: 60_000,
    });
    expect(first).toMatchObject({ status: "found", fromCache: false });

    clock.advance(30_000);
    const second = await fetchRdapDomain({
      registry,
      clock,
      client,
      cache,
      registrableDomain: "example.com",
      cacheTtlMs: 60_000,
    });
    expect(second).toMatchObject({ status: "found", fromCache: true });
    expect(client.requests).toHaveLength(1); // no second network call while fresh

    clock.advance(60_000); // now past expiry
    const third = await fetchRdapDomain({
      registry,
      clock,
      client,
      cache,
      registrableDomain: "example.com",
      cacheTtlMs: 60_000,
    });
    expect(third).toMatchObject({ status: "found", fromCache: false });
    expect(client.requests).toHaveLength(2);
  });

  it("caps redirects at the safe hard limit", () => {
    expect(DEFAULT_RDAP_MAX_REDIRECTS).toBeLessThanOrEqual(5);
  });
});

// --- M2 contract conformance ------------------------------------------------

describe("RDAP source descriptor", () => {
  it("is a valid M2 descriptor that discloses only the registrable domain", () => {
    expect(() => assertValidSourceDescriptor(RDAP_SOURCE_DESCRIPTOR)).not.toThrow();
    expect(RDAP_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["registrable-domain"]);
    expect(RDAP_SOURCE_DESCRIPTOR.credentials.kind).toBe("none");
  });

  it("preflights cleanly with no credential and no consent gate", () => {
    const preflight = preflightOnlineSource(RDAP_SOURCE_DESCRIPTOR, {
      commercialMode: "commercial",
    });
    expect(preflight.ok).toBe(true);
    if (preflight.ok) expect(preflight.credential).toBeNull();
  });
});
