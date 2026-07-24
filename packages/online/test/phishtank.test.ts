import { describe, expect, it } from "vitest";

import {
  parsePhishTankCsv,
  PHISHTANK_DATA_BASE_URL,
  PHISHTANK_SOURCE_DESCRIPTOR,
  PHISHTANK_SOURCE_ID,
  updatePhishTankSnapshot,
  type PhishTankHttpClient,
  type PhishTankHttpRequest,
  type PhishTankHttpResponse,
  type PhishTankSnapshot,
  type PhishTankSnapshotMetadata,
  type PhishTankSnapshotStore,
} from "../src/mirrors/index.js";
import {
  assertValidSourceDescriptor,
  createOnlineSecret,
} from "../src/sources/index.js";
import { assertOnlineSourceContract } from "./contract/online-source-contract-kit.js";

// --- Fixtures ---------------------------------------------------------------

const APP_KEY = "phishtank-app-key-xyz789";

const HEADER =
  "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target";

const ROW_A =
  '"8000001","http://evil.example/login","http://www.phishtank.com/phish_detail.php?phish_id=8000001","2026-07-20T12:00:00+00:00","yes","2026-07-20T13:00:00+00:00","yes","PayPal"';
const ROW_B =
  '"8000002","https://phish.example/verify","http://www.phishtank.com/phish_detail.php?phish_id=8000002","2026-07-19T09:00:00+00:00","no","","no","Other"';

function csv(...rows: string[]): string {
  return [HEADER, ...rows].join("\n") + "\n";
}

class ScriptedClient implements PhishTankHttpClient {
  readonly requests: PhishTankHttpRequest[] = [];
  private readonly queue: PhishTankHttpResponse[];
  constructor(...responses: PhishTankHttpResponse[]) {
    this.queue = responses;
  }
  request(request: PhishTankHttpRequest): Promise<PhishTankHttpResponse> {
    this.requests.push(request);
    const next = this.queue.shift();
    if (next === undefined) throw new Error("ScriptedClient exhausted");
    return Promise.resolve(next);
  }
}

class ThrowingClient implements PhishTankHttpClient {
  request(): Promise<PhishTankHttpResponse> {
    return Promise.reject(new TypeError("connection reset"));
  }
}

class MemoryStore implements PhishTankSnapshotStore {
  replaced = 0;
  private snapshot: PhishTankSnapshot | null;
  constructor(initial: PhishTankSnapshot | null = null) {
    this.snapshot = initial;
  }
  readMetadata(): Promise<PhishTankSnapshotMetadata | null> {
    return Promise.resolve(this.snapshot?.metadata ?? null);
  }
  replace(snapshot: PhishTankSnapshot): Promise<void> {
    this.replaced++;
    this.snapshot = snapshot;
    return Promise.resolve();
  }
  current(): PhishTankSnapshot | null {
    return this.snapshot;
  }
}

const clockAt = (iso: string) => ({ now: () => new Date(iso) });

function resp(
  status: number,
  body = "",
  headers: Record<string, string> = {},
): PhishTankHttpResponse {
  return { status, body, headers };
}

function baseOptions(client: PhishTankHttpClient, store: PhishTankSnapshotStore) {
  return {
    client,
    store,
    appKey: createOnlineSecret(APP_KEY),
    clock: clockAt("2026-07-24T06:00:00.000Z"),
  };
}

function seededStore(etag: string, observedAt: string): MemoryStore {
  const metadata: PhishTankSnapshotMetadata = {
    source: PHISHTANK_SOURCE_ID,
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
        phishId: "1",
        url: "http://old.example/x",
        detailUrl: null,
        submissionTime: null,
        verified: true,
        verificationTime: null,
        online: true,
        target: null,
      },
    ],
  });
}

// --- Descriptor + contract kit ----------------------------------------------

describe("PHISHTANK_SOURCE_DESCRIPTOR", () => {
  it("is a valid caller-owned mirror descriptor with an app-key credential", () => {
    expect(() => assertValidSourceDescriptor(PHISHTANK_SOURCE_DESCRIPTOR)).not.toThrow();
    expect(PHISHTANK_SOURCE_DESCRIPTOR.dataOrigin).toEqual({
      kind: "caller-owned-mirror",
      bundled: false,
    });
    expect(PHISHTANK_SOURCE_DESCRIPTOR.disclosure.sends).toEqual(["none"]);
    expect(PHISHTANK_SOURCE_DESCRIPTOR.credentials).toMatchObject({
      kind: "required",
      scheme: "app-key",
    });
    expect(PHISHTANK_SOURCE_DESCRIPTOR.terms.supportedModes).not.toContain("commercial");
  });

  it("passes the shared online-source contract battery", () => {
    assertOnlineSourceContract(PHISHTANK_SOURCE_DESCRIPTOR, { sampleCredential: APP_KEY });
  });
});

// --- CSV parser -------------------------------------------------------------

describe("parsePhishTankCsv", () => {
  it("parses normalized records and yes/no + timestamps", () => {
    const parsed = parsePhishTankCsv(csv(ROW_A, ROW_B));
    expect(parsed).not.toBeNull();
    expect(parsed!.records).toHaveLength(2);
    expect(parsed!.records[0]).toEqual({
      phishId: "8000001",
      url: "http://evil.example/login",
      detailUrl: "http://www.phishtank.com/phish_detail.php?phish_id=8000001",
      submissionTime: "2026-07-20T12:00:00.000Z",
      verified: true,
      verificationTime: "2026-07-20T13:00:00.000Z",
      online: true,
      target: "PayPal",
    });
    expect(parsed!.records[1]).toMatchObject({
      phishId: "8000002",
      verified: false,
      online: false,
      verificationTime: null,
    });
  });

  it("accepts a header-only (zero-record) feed", () => {
    const parsed = parsePhishTankCsv(csv());
    expect(parsed).not.toBeNull();
    expect(parsed!.records).toEqual([]);
  });

  it("rejects a non-PhishTank body as malformed (null)", () => {
    expect(parsePhishTankCsv("<html>403</html>")).toBeNull();
    expect(parsePhishTankCsv('{"errortext":"invalid key"}')).toBeNull();
    expect(parsePhishTankCsv("")).toBeNull();
  });
});

// --- Updater ----------------------------------------------------------------

describe("updatePhishTankSnapshot", () => {
  it("builds the keyed URL, sends the user agent, and writes a snapshot", async () => {
    const client = new ScriptedClient(resp(200, csv(ROW_A, ROW_B), { ETag: '"p7"' }));
    const store = new MemoryStore();
    const result = await updatePhishTankSnapshot({
      ...baseOptions(client, store),
      userAgent: "phishtank/test-user",
    });

    expect(result.status).toBe("updated");
    expect(client.requests[0]!.url).toBe(
      `${PHISHTANK_DATA_BASE_URL}/${APP_KEY}/online-valid.csv`,
    );
    expect(client.requests[0]!.headers["User-Agent"]).toBe("phishtank/test-user");
    if (result.status === "updated") {
      expect(result.snapshot.records).toHaveLength(2);
      expect(result.snapshot.metadata).toMatchObject({
        source: PHISHTANK_SOURCE_ID,
        etag: '"p7"',
        observedAt: "2026-07-24T06:00:00.000Z",
        // Default hourly cadence drives expiry.
        expiresAt: "2026-07-24T07:00:00.000Z",
        recordCount: 2,
      });
    }
  });

  it("never leaks the app key into the snapshot, metadata, or result", async () => {
    const client = new ScriptedClient(resp(200, csv(ROW_A), { ETag: '"p1"' }));
    const store = new MemoryStore();
    const result = await updatePhishTankSnapshot(baseOptions(client, store));
    expect(JSON.stringify(result)).not.toContain(APP_KEY);
    expect(JSON.stringify(store.current())).not.toContain(APP_KEY);
    // The key necessarily appears only in the outbound request URL.
    expect(client.requests[0]!.url).toContain(APP_KEY);
  });

  it("sends conditional headers and returns unchanged on 304", async () => {
    const seeded = seededStore('"p7"', "2026-07-24T05:00:00.000Z");
    const client = new ScriptedClient(resp(304));
    const result = await updatePhishTankSnapshot({
      ...baseOptions(client, seeded),
      cadenceMs: 60_000,
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });
    expect(client.requests[0]!.headers["If-None-Match"]).toBe('"p7"');
    expect(result.status).toBe("unchanged");
    if (result.status === "unchanged") expect(result.reason).toBe("not-modified");
    expect(seeded.replaced).toBe(0);
  });

  it("short-circuits within the hourly cadence without a request", async () => {
    const seeded = seededStore('"p7"', "2026-07-24T05:30:00.000Z");
    const client = new ScriptedClient();
    const result = await updatePhishTankSnapshot({
      ...baseOptions(client, seeded),
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });
    expect(client.requests).toHaveLength(0);
    expect(result.status).toBe("unchanged");
    if (result.status === "unchanged") expect(result.reason).toBe("within-cadence");
  });

  it("treats a non-CSV body as malformed and preserves the old snapshot", async () => {
    const seeded = seededStore('"p7"', "2026-07-24T00:00:00.000Z");
    const before = seeded.current();
    const client = new ScriptedClient(resp(200, "<html>Access Denied</html>"));
    const result = await updatePhishTankSnapshot({
      ...baseOptions(client, seeded),
      cadenceMs: 60_000,
      clock: clockAt("2026-07-24T06:00:00.000Z"),
    });
    expect(result.status).toBe("failure");
    if (result.status === "failure") expect(result.cause.code).toBe("phishtank-malformed");
    expect(seeded.replaced).toBe(0);
    expect(seeded.current()).toBe(before);
  });

  it.each([429, 509])("maps %i to a retryable throttled skip", async (status) => {
    const client = new ScriptedClient(resp(status, "", { "Retry-After": "3600" }));
    const store = new MemoryStore();
    const result = await updatePhishTankSnapshot(baseOptions(client, store));
    expect(result.status).toBe("skipped");
    if (result.status === "skipped") {
      expect(result.cause.code).toBe("phishtank-throttled");
      expect(result.cause.retryable).toBe(true);
      expect(result.cause.details).toMatchObject({ status, retryAfter: "3600" });
    }
    expect(store.replaced).toBe(0);
  });

  it("maps a non-2xx status to an http-error failure", async () => {
    const result = await updatePhishTankSnapshot(
      baseOptions(new ScriptedClient(resp(500, "err")), new MemoryStore()),
    );
    expect(result.status).toBe("failure");
    if (result.status === "failure") {
      expect(result.cause.code).toBe("phishtank-http-error");
      expect(result.cause.details).toMatchObject({ status: 500 });
    }
  });

  it("maps a thrown request to a network-error failure", async () => {
    const result = await updatePhishTankSnapshot(
      baseOptions(new ThrowingClient(), new MemoryStore()),
    );
    expect(result.status).toBe("failure");
    if (result.status === "failure") expect(result.cause.code).toBe("phishtank-network-error");
  });

  it("skips before any request when already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const client = new ScriptedClient();
    const result = await updatePhishTankSnapshot({
      ...baseOptions(client, new MemoryStore()),
      signal: controller.signal,
    });
    expect(client.requests).toHaveLength(0);
    expect(result.status).toBe("skipped");
    if (result.status === "skipped") expect(result.cause.code).toBe("phishtank-caller-aborted");
  });

  it("disables cadence and expiry when cadenceMs is non-positive", async () => {
    const client = new ScriptedClient(resp(200, csv(ROW_A)));
    const store = new MemoryStore();
    const result = await updatePhishTankSnapshot({ ...baseOptions(client, store), cadenceMs: 0 });
    expect(result.status).toBe("updated");
    if (result.status === "updated") expect(result.snapshot.metadata.expiresAt).toBeNull();
  });
});
