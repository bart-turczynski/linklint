import { describe, expect, it } from "vitest";

import {
  parseUrlhausCsv,
  updateUrlhausSnapshot,
  URLHAUS_ONLINE_DUMP_URL,
  URLHAUS_SOURCE_DESCRIPTOR,
  URLHAUS_SOURCE_ID,
  type UrlhausHttpClient,
  type UrlhausHttpRequest,
  type UrlhausHttpResponse,
  type UrlhausSnapshot,
  type UrlhausSnapshotMetadata,
  type UrlhausSnapshotStore,
} from "../src/mirrors/index.js";
import {
  assertValidSourceDescriptor,
  createOnlineSecret,
} from "../src/sources/index.js";
import { assertOnlineSourceContract } from "./contract/online-source-contract-kit.js";

// --- Fixtures ---------------------------------------------------------------

const AUTH_KEY = "urlhaus-auth-key-abc123";

const CSV_HEADER = [
  "# URLhaus Database Dump (CSV - only online URLs)",
  "# Last updated: 2026-07-24 00:00:00 (UTC)",
  '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
].join("\n");

function csv(...rows: string[]): string {
  return [CSV_HEADER, ...rows].join("\n") + "\n";
}

const ROW_A =
  '"3001","2026-07-23 12:00:00","http://malware.example/a.exe","online","2026-07-24 00:00:00","malware_download","exe,elf","https://urlhaus.abuse.ch/url/3001/","anonymous"';
const ROW_B =
  '"3002","2026-07-22 09:30:00","https://evil.example/b.bin","offline","","malware_download","","https://urlhaus.abuse.ch/url/3002/","reporterX"';

/** A scripted client that records requests and replays a queue of responses. */
class ScriptedClient implements UrlhausHttpClient {
  readonly requests: UrlhausHttpRequest[] = [];
  private readonly queue: UrlhausHttpResponse[];

  constructor(...responses: UrlhausHttpResponse[]) {
    this.queue = responses;
  }

  request(request: UrlhausHttpRequest): Promise<UrlhausHttpResponse> {
    this.requests.push(request);
    const next = this.queue.shift();
    if (next === undefined) throw new Error("ScriptedClient exhausted");
    return Promise.resolve(next);
  }
}

/** A client that always throws, to exercise the network-error branch. */
class ThrowingClient implements UrlhausHttpClient {
  request(): Promise<UrlhausHttpResponse> {
    return Promise.reject(new TypeError("connection reset"));
  }
}

/** An in-memory caller-owned store. Tracks how many times it was replaced. */
class MemoryStore implements UrlhausSnapshotStore {
  replaced = 0;
  private snapshot: UrlhausSnapshot | null;

  constructor(initial: UrlhausSnapshot | null = null) {
    this.snapshot = initial;
  }

  readMetadata(): Promise<UrlhausSnapshotMetadata | null> {
    return Promise.resolve(this.snapshot?.metadata ?? null);
  }

  replace(snapshot: UrlhausSnapshot): Promise<void> {
    this.replaced++;
    this.snapshot = snapshot;
    return Promise.resolve();
  }

  current(): UrlhausSnapshot | null {
    return this.snapshot;
  }
}

const clockAt = (iso: string) => ({ now: () => new Date(iso) });

function resp(
  status: number,
  body = "",
  headers: Record<string, string> = {},
): UrlhausHttpResponse {
  return { status, body, headers };
}

function baseOptions(client: UrlhausHttpClient, store: UrlhausSnapshotStore) {
  return {
    client,
    store,
    credential: createOnlineSecret(AUTH_KEY),
    clock: clockAt("2026-07-24T06:00:00.000Z"),
  };
}

// --- Descriptor + contract kit ----------------------------------------------

describe("URLHAUS_SOURCE_DESCRIPTOR", () => {
  it("is a valid caller-owned mirror descriptor", () => {
    expect(() => assertValidSourceDescriptor(URLHAUS_SOURCE_DESCRIPTOR)).not.toThrow();
    expect(URLHAUS_SOURCE_DESCRIPTOR.id).toBe(URLHAUS_SOURCE_ID);
    expect(URLHAUS_SOURCE_DESCRIPTOR.dataOrigin).toEqual({
      kind: "caller-owned-mirror",
      bundled: false,
    });
    expect(URLHAUS_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["none"]);
    expect(URLHAUS_SOURCE_DESCRIPTOR.credentials).toMatchObject({
      kind: "required",
      scheme: "auth-key",
    });
    expect(URLHAUS_SOURCE_DESCRIPTOR.terms.supportedModes).not.toContain("commercial");
  });

  it("passes the shared online-source contract battery", () => {
    assertOnlineSourceContract(URLHAUS_SOURCE_DESCRIPTOR, { sampleCredential: AUTH_KEY });
  });
});

// --- CSV parser -------------------------------------------------------------

describe("parseUrlhausCsv", () => {
  it("parses normalized records and ISO-normalizes timestamps", () => {
    const parsed = parseUrlhausCsv(csv(ROW_A, ROW_B));
    expect(parsed).not.toBeNull();
    expect(parsed!.records).toHaveLength(2);
    expect(parsed!.records[0]).toEqual({
      id: "3001",
      url: "http://malware.example/a.exe",
      dateAdded: "2026-07-23T12:00:00.000Z",
      status: "online",
      lastOnline: "2026-07-24T00:00:00.000Z",
      threat: "malware_download",
      tags: ["exe", "elf"],
      reporter: "anonymous",
    });
    expect(parsed!.records[1]).toMatchObject({
      id: "3002",
      status: "offline",
      lastOnline: null,
      tags: [],
    });
  });

  it("accepts an empty (zero-record) dump that still carries the abuse.ch header", () => {
    const parsed = parseUrlhausCsv(csv());
    expect(parsed).not.toBeNull();
    expect(parsed!.records).toEqual([]);
  });

  it("rejects a body that is not a URLhaus CSV as malformed (null)", () => {
    expect(parseUrlhausCsv("<html><body>403 Forbidden</body></html>")).toBeNull();
    expect(parseUrlhausCsv('{"error":"invalid auth key"}')).toBeNull();
    expect(parseUrlhausCsv("")).toBeNull();
  });

  it("skips rows without an id or URL rather than fabricating one", () => {
    const parsed = parseUrlhausCsv(
      csv('"","2026-07-23 12:00:00","","online","","malware_download","","link","r"', ROW_A),
    );
    expect(parsed!.records).toHaveLength(1);
    expect(parsed!.records[0]!.id).toBe("3001");
  });
});

// --- Updater ----------------------------------------------------------------

describe("updateUrlhausSnapshot", () => {
  it("authenticates with the Auth-Key header and writes a fresh snapshot", async () => {
    const client = new ScriptedClient(
      resp(200, csv(ROW_A, ROW_B), { ETag: '"v7"', "Last-Modified": "Fri, 24 Jul 2026 00:00:00 GMT" }),
    );
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot({
      ...baseOptions(client, store),
      cadenceMs: 3_600_000,
    });

    expect(result.status).toBe("updated");
    expect(client.requests[0]!.url).toBe(URLHAUS_ONLINE_DUMP_URL);
    expect(client.requests[0]!.headers["Auth-Key"]).toBe(AUTH_KEY);
    expect(store.replaced).toBe(1);
    if (result.status === "updated") {
      expect(result.snapshot.records).toHaveLength(2);
      expect(result.snapshot.metadata).toMatchObject({
        source: URLHAUS_SOURCE_ID,
        etag: '"v7"',
        lastModified: "Fri, 24 Jul 2026 00:00:00 GMT",
        observedAt: "2026-07-24T06:00:00.000Z",
        expiresAt: "2026-07-24T07:00:00.000Z",
        recordCount: 2,
      });
    }
  });

  it("never leaks the Auth-Key into the snapshot, metadata, or result", async () => {
    const client = new ScriptedClient(resp(200, csv(ROW_A), { ETag: '"v1"' }));
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot(baseOptions(client, store));
    expect(JSON.stringify(result)).not.toContain(AUTH_KEY);
    expect(JSON.stringify(store.current())).not.toContain(AUTH_KEY);
  });

  it("sends conditional headers and returns unchanged on 304", async () => {
    const seeded = seededStore('"v7"', "2026-07-24T05:00:00.000Z");
    const client = new ScriptedClient(resp(304));
    const result = await updateUrlhausSnapshot({
      ...baseOptions(client, seeded),
      // Force past the cadence window so a network refresh is attempted.
      cadenceMs: 60_000,
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });

    expect(client.requests[0]!.headers["If-None-Match"]).toBe('"v7"');
    expect(result.status).toBe("unchanged");
    if (result.status === "unchanged") expect(result.reason).toBe("not-modified");
    expect(seeded.replaced).toBe(0);
  });

  it("short-circuits within the refresh cadence without contacting the provider", async () => {
    const seeded = seededStore('"v7"', "2026-07-24T05:55:00.000Z");
    const client = new ScriptedClient(); // exhausted: any request would throw
    const result = await updateUrlhausSnapshot({
      ...baseOptions(client, seeded),
      cadenceMs: 3_600_000,
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });

    expect(client.requests).toHaveLength(0);
    expect(result.status).toBe("unchanged");
    if (result.status === "unchanged") expect(result.reason).toBe("within-cadence");
  });

  it("treats a non-CSV body as a malformed failure and preserves the old snapshot", async () => {
    const seeded = seededStore('"v7"', "2026-07-24T00:00:00.000Z");
    const before = seeded.current();
    const client = new ScriptedClient(resp(200, "<html>Access Denied</html>"));
    const result = await updateUrlhausSnapshot({
      ...baseOptions(client, seeded),
      cadenceMs: 60_000,
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });

    expect(result.status).toBe("failure");
    if (result.status === "failure") expect(result.cause.code).toBe("urlhaus-malformed");
    expect(seeded.replaced).toBe(0);
    expect(seeded.current()).toBe(before);
  });

  it("maps 429 to a retryable skip carrying Retry-After", async () => {
    const client = new ScriptedClient(resp(429, "", { "Retry-After": "120" }));
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot(baseOptions(client, store));

    expect(result.status).toBe("skipped");
    if (result.status === "skipped") {
      expect(result.cause.code).toBe("urlhaus-throttled");
      expect(result.cause.retryable).toBe(true);
      expect(result.cause.details).toMatchObject({ retryAfter: "120" });
    }
    expect(store.replaced).toBe(0);
  });

  it("maps a non-2xx status to an http-error failure", async () => {
    const client = new ScriptedClient(resp(500, "server error"));
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot(baseOptions(client, store));
    expect(result.status).toBe("failure");
    if (result.status === "failure") {
      expect(result.cause.code).toBe("urlhaus-http-error");
      expect(result.cause.details).toMatchObject({ status: 500 });
    }
  });

  it("maps a thrown request to a network-error failure", async () => {
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot(baseOptions(new ThrowingClient(), store));
    expect(result.status).toBe("failure");
    if (result.status === "failure") expect(result.cause.code).toBe("urlhaus-network-error");
  });

  it("skips before any request when the caller has already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const client = new ScriptedClient();
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot({
      ...baseOptions(client, store),
      signal: controller.signal,
    });

    expect(client.requests).toHaveLength(0);
    expect(result.status).toBe("skipped");
    if (result.status === "skipped") expect(result.cause.code).toBe("urlhaus-caller-aborted");
  });

  it("declares no expiry when no cadence is configured", async () => {
    const client = new ScriptedClient(resp(200, csv(ROW_A)));
    const store = new MemoryStore();
    const result = await updateUrlhausSnapshot(baseOptions(client, store));
    expect(result.status).toBe("updated");
    if (result.status === "updated") expect(result.snapshot.metadata.expiresAt).toBeNull();
  });
});

/** A store seeded with one prior snapshot at the given ETag and observation time. */
function seededStore(etag: string, observedAt: string): MemoryStore {
  const metadata: UrlhausSnapshotMetadata = {
    source: URLHAUS_SOURCE_ID,
    version: "1.0.0",
    etag,
    lastModified: null,
    observedAt,
    expiresAt: null,
    recordCount: 1,
  };
  return new MemoryStore({
    metadata,
    records: [
      {
        id: "1",
        url: "http://old.example/x",
        dateAdded: null,
        status: "online",
        lastOnline: null,
        threat: null,
        tags: [],
        reporter: null,
      },
    ],
  });
}
