/**
 * Live coverage for the concrete Node mirror HTTP clients (LINK-mpkglaqb).
 *
 * Every other URLhaus and PhishTank test injects a fake client, so the real
 * socket, header, decode and address-policy wiring would otherwise have no
 * behavioral coverage at all — which is exactly how both updaters shipped with
 * no runnable client behind them.
 *
 * Uses a loopback server, so it needs no external network. The real address
 * policy correctly refuses loopback, so most cases inject a permissive
 * classifier; the refusal itself is proved separately against the DEFAULT
 * policy, which is what keeps the permissive seam from being a silent hole.
 * `allowInsecureUrl` is the second seam, and gets the same treatment: the
 * default refusal of a cleartext credentialed URL is proved on its own.
 *
 * The last block runs the SHIPPED `updateUrlhausSnapshot` /
 * `updatePhishTankSnapshot` through the real clients against the loopback
 * server, which is the end-to-end claim the issue was actually about: a caller
 * can now refresh a mirror with what the package provides.
 */
import { createServer, type Server } from "node:http";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { createOnlineSecret } from "../src/sources/index.js";
import { createNodePhishTankHttpClient } from "../src/mirrors/phishtank-node.js";
import { createNodeUrlhausHttpClient } from "../src/mirrors/urlhaus-node.js";
import { updatePhishTankSnapshot } from "../src/mirrors/phishtank-updater.js";
import { updateUrlhausSnapshot } from "../src/mirrors/urlhaus-updater.js";
import type { NodeMirrorHttpClientOptions } from "../src/mirrors/mirror-http-node.js";
import type {
  PhishTankSnapshot,
  PhishTankSnapshotMetadata,
  PhishTankSnapshotStore,
} from "../src/mirrors/phishtank-types.js";
import type {
  UrlhausSnapshot,
  UrlhausSnapshotMetadata,
  UrlhausSnapshotStore,
} from "../src/mirrors/types.js";
import type { TransportAddressDecision } from "../src/transport/types.js";
import { deadLoopbackPort } from "./proxy-isolation-harness.js";

let server: Server | undefined;

afterEach(async () => {
  const running = server;
  server = undefined;
  if (running === undefined) return;
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

interface Reply {
  readonly status: number;
  readonly headers?: Record<string, string | string[]>;
  readonly body?: string | Buffer;
}

async function startServer(
  handler: (
    path: string,
    headers: Record<string, string | string[] | undefined>,
  ) => Reply | Promise<Reply>,
): Promise<number> {
  const created = createServer((req, res) => {
    void Promise.resolve(handler(req.url ?? "/", req.headers)).then((reply) => {
      res.writeHead(reply.status, reply.headers ?? {});
      res.end(reply.body ?? "");
    });
  });
  server = created;
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

/**
 * The test seams: loopback is the only address a hermetic server can bind and
 * the shipped policy refuses it, and a loopback server speaks cleartext while
 * the shipped scheme policy refuses that too. Everything else about the
 * classifier's shape is preserved so the client's own handling is under test.
 */
function allowLoopback(address: string): TransportAddressDecision {
  return { address, family: address.includes(":") ? 6 : 4, allowed: true, category: null };
}

const SEAMS = { classifyAddress: allowLoopback, allowInsecureUrl: true } as const;

type Seamless = Omit<NodeMirrorHttpClientOptions, "classifyAddress" | "allowInsecureUrl">;

function urlhaus(options: Seamless = {}) {
  return createNodeUrlhausHttpClient({ ...options, ...SEAMS });
}

function phishtank(options: Seamless = {}) {
  return createNodePhishTankHttpClient({ ...options, ...SEAMS });
}

async function failureOf(
  promise: Promise<unknown>,
): Promise<{ name?: unknown; code?: unknown; detail?: unknown }> {
  const error = await promise.then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(error).not.toBeNull();
  return error as { name?: unknown; code?: unknown; detail?: unknown };
}

const URLHAUS_CSV = [
  '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
  '"1","2026-01-02 03:04:05","http://malware.example/a.bin","online","2026-01-02 03:04:05","malware_download","exe","https://urlhaus.abuse.ch/url/1/","rep"',
].join("\n");

const PHISHTANK_CSV = [
  "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target",
  "9001,http://phish.example/login,https://www.phishtank.com/phish_detail.php?phish_id=9001,2026-01-02T03:04:05+00:00,yes,2026-01-02T04:00:00+00:00,yes,PayPal",
].join("\n");

describe("node URLhaus HTTP client (live loopback)", () => {
  it("returns the decoded dump and forwards the Auth-Key header verbatim", async () => {
    let seenPath = "";
    let seenHeaders: Record<string, string | string[] | undefined> = {};
    const port = await startServer((path, headers) => {
      seenPath = path;
      seenHeaders = headers;
      return { status: 200, headers: { "content-type": "text/csv" }, body: URLHAUS_CSV };
    });

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: { "Auth-Key": "secret-auth-key" },
    });

    expect(response.status).toBe(200);
    expect(response.body).toBe(URLHAUS_CSV);
    expect(response.headers["content-type"]).toBe("text/csv");
    expect(seenPath).toBe("/downloads/csv_online/");
    // The credential is revealed into exactly the header the updater named,
    // lower-cased on the wire as HTTP field names always are.
    expect(seenHeaders["auth-key"]).toBe("secret-auth-key");
    // And nothing ambient rides along with it.
    expect(seenHeaders.authorization).toBeUndefined();
    expect(seenHeaders.cookie).toBeUndefined();
    expect(seenHeaders["user-agent"]).toBeUndefined();
  });

  it("sends conditional validators the updater supplies", async () => {
    let seen: Record<string, string | string[] | undefined> = {};
    const port = await startServer((_path, headers) => {
      seen = headers;
      return { status: 304 };
    });

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: {
        "Auth-Key": "k",
        "If-None-Match": '"abc"',
        "If-Modified-Since": "Wed, 21 Oct 2026 07:28:00 GMT",
      },
    });

    expect(response.status).toBe(304);
    expect(response.body).toBe("");
    expect(seen["if-none-match"]).toBe('"abc"');
    expect(seen["if-modified-since"]).toBe("Wed, 21 Oct 2026 07:28:00 GMT");
  });

  it("decodes a gzip-encoded dump", async () => {
    const port = await startServer(() => ({
      status: 200,
      headers: { "content-encoding": "gzip", "content-type": "text/csv" },
      body: gzipSync(Buffer.from(URLHAUS_CSV, "utf8")),
    }));

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.body).toBe(URLHAUS_CSV);
  });

  it("returns a 429 as an ordinary response so the updater can call it a throttle", async () => {
    const port = await startServer(() => ({
      status: 429,
      headers: { "retry-after": "600" },
    }));

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.status).toBe(429);
    expect(response.headers["retry-after"]).toBe("600");
  });

  /** The credential must never be re-sent to a host the caller did not name. */
  it("returns a 3xx with its Location header without following it", async () => {
    const paths: string[] = [];
    const port = await startServer((path) => {
      paths.push(path);
      if (path === "/downloads/csv_online/") {
        return { status: 302, headers: { location: "/elsewhere" } };
      }
      return { status: 200, body: URLHAUS_CSV };
    });

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe("/elsewhere");
    expect(paths).toEqual(["/downloads/csv_online/"]);
  });

  it("reports a refused connection as a typed failure", async () => {
    const port = await deadLoopbackPort();

    const failure = await failureOf(
      urlhaus().request({ url: `http://127.0.0.1:${port}/x`, headers: { "Auth-Key": "k" } }),
    );

    expect(failure.name).toBe("UrlhausHttpFailure");
    expect(failure.code).toBe("connect-refused");
  });

  it("reports a caller abort as an AbortError", async () => {
    const controller = new AbortController();
    const port = await startServer(
      () =>
        new Promise<Reply>(() => {
          controller.abort();
        }),
    );

    const failure = await failureOf(
      urlhaus().request({
        url: `http://127.0.0.1:${port}/slow`,
        headers: { "Auth-Key": "k" },
        signal: controller.signal,
      }),
    );

    expect(failure.name).toBe("AbortError");
  });

  it("refuses a request aborted before it starts", async () => {
    const controller = new AbortController();
    controller.abort();

    const failure = await failureOf(
      urlhaus().request({
        url: "http://127.0.0.1:1/x",
        headers: { "Auth-Key": "k" },
        signal: controller.signal,
      }),
    );

    expect(failure.name).toBe("AbortError");
  });

  it("stops an oversized dump at the configured budget", async () => {
    const port = await startServer(() => ({ status: 200, body: "x".repeat(4_096) }));

    const failure = await failureOf(
      urlhaus({ policy: { maxResponseBytes: 512 } }).request({
        url: `http://127.0.0.1:${port}/x`,
        headers: { "Auth-Key": "k" },
      }),
    );

    expect(failure.code).toBe("response-too-large");
  });

  it("accepts a dump that fits the configured budget", async () => {
    // Guards against a vacuous pass above: the same shape under a budget it
    // fits must still complete.
    const port = await startServer(() => ({ status: 200, body: "x".repeat(4_096) }));

    const response = await urlhaus({ policy: { maxResponseBytes: 8_192 } }).request({
      url: `http://127.0.0.1:${port}/x`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.body.length).toBe(4_096);
  });

  it("accepts a multi-megabyte dump under the raised mirror default", async () => {
    // The point of DEFAULT_MIRROR_DOWNLOAD_POLICY: L0's 1 MiB body budget would
    // refuse every real feed export, so a payload over that bound must pass
    // with NO caller policy at all.
    const payload = "y".repeat(2 * 1_048_576);
    const port = await startServer(() => ({ status: 200, body: payload }));

    const response = await urlhaus().request({
      url: `http://127.0.0.1:${port}/x`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.body.length).toBe(payload.length);
  });

  it("refuses an oversized response head with a header-budget cause", async () => {
    const port = await startServer(() => ({
      status: 200,
      headers: { "x-pad": "p".repeat(2_000) },
      body: "unreachable",
    }));

    // Below the 2 KB head AND below Node's 16 KB default, so a pass proves this
    // bound was applied rather than the runtime's.
    const failure = await failureOf(
      urlhaus({ policy: { maxResponseHeaderBytes: 512 } }).request({
        url: `http://127.0.0.1:${port}/x`,
        headers: { "Auth-Key": "k" },
      }),
    );

    expect(failure.code).toBe("response-headers-too-large");
  });
});

describe("node PhishTank HTTP client (live loopback)", () => {
  it("returns the decoded feed and sends the descriptive User-Agent", async () => {
    let seenPath = "";
    let seenAgent: string | string[] | undefined;
    const port = await startServer((path, headers) => {
      seenPath = path;
      seenAgent = headers["user-agent"];
      return { status: 200, headers: { "content-type": "text/csv" }, body: PHISHTANK_CSV };
    });

    const response = await phishtank().request({
      url: `http://127.0.0.1:${port}/data/app-key-in-the-path/online-valid.csv`,
      headers: { "User-Agent": "phishtank/tester" },
    });

    expect(response.status).toBe(200);
    expect(response.body).toBe(PHISHTANK_CSV);
    // The app key rides in the path, and the path is transmitted verbatim.
    expect(seenPath).toBe("/data/app-key-in-the-path/online-valid.csv");
    expect(seenAgent).toBe("phishtank/tester");
  });

  it("returns a 509 bandwidth-exceeded as an ordinary response", async () => {
    const port = await startServer(() => ({ status: 509 }));

    const response = await phishtank().request({
      url: `http://127.0.0.1:${port}/data/k/online-valid.csv`,
      headers: { "User-Agent": "phishtank/tester" },
    });

    expect(response.status).toBe(509);
  });

  it("decodes a gzip-encoded feed", async () => {
    const port = await startServer(() => ({
      status: 200,
      headers: { "content-encoding": "gzip" },
      body: gzipSync(Buffer.from(PHISHTANK_CSV, "utf8")),
    }));

    const response = await phishtank().request({
      url: `http://127.0.0.1:${port}/data/k/online-valid.csv`,
      headers: { "User-Agent": "phishtank/tester" },
    });

    expect(response.body).toBe(PHISHTANK_CSV);
  });

  it("names itself in its typed failures so the updater's cause is legible", async () => {
    const port = await deadLoopbackPort();

    const failure = await failureOf(
      phishtank().request({
        url: `http://127.0.0.1:${port}/data/k/online-valid.csv`,
        headers: { "User-Agent": "phishtank/tester" },
      }),
    );

    expect(failure.name).toBe("PhishTankHttpFailure");
    expect(failure.code).toBe("connect-refused");
  });
});

/**
 * The seams above are permissive on purpose. These cases run the SHIPPED
 * defaults, and are what stop the seams from being silent holes.
 */
describe("node mirror clients under the shipped default policy", () => {
  it("refuses a prohibited IP-LITERAL address before connecting", async () => {
    // `net.connect` skips DNS entirely for a literal host, so the lookup gate
    // never sees this URL — the literal has to be classified on its own path or
    // a configured dump URL written as a bare address walks past the policy.
    let reached = false;
    const port = await startServer(() => {
      reached = true;
      return { status: 200, body: URLHAUS_CSV };
    });

    const failure = await failureOf(
      createNodeUrlhausHttpClient({ allowInsecureUrl: true }).request({
        url: `http://127.0.0.1:${port}/x`,
        headers: { "Auth-Key": "k" },
      }),
    );

    expect(failure.name).toBe("UrlhausHttpFailure");
    expect(failure.code).toBe("prohibited-address");
    expect(reached).toBe(false);
  });

  it("refuses a prohibited RESOLVED address before connecting", async () => {
    // The other half of the gate: a hostname whose answers are prohibited. The
    // classification happens inside the `dns.lookup` replacement, so Node only
    // ever receives answers that passed.
    let reached = false;
    const port = await startServer(() => {
      reached = true;
      return { status: 200, body: PHISHTANK_CSV };
    });

    const failure = await failureOf(
      createNodePhishTankHttpClient({ allowInsecureUrl: true }).request({
        url: `http://localhost:${port}/data/k/online-valid.csv`,
        headers: { "User-Agent": "phishtank/tester" },
      }),
    );

    expect(failure.code).toBe("prohibited-address");
    expect(reached).toBe(false);
  });

  /**
   * The scheme gate, and the reason it exists here but not on the RDAP client:
   * every one of these requests carries a caller credential.
   */
  it("refuses a cleartext URLhaus dump URL rather than sending the Auth-Key over it", async () => {
    const failure = await failureOf(
      createNodeUrlhausHttpClient({ classifyAddress: allowLoopback }).request({
        url: "http://127.0.0.1:1/downloads/csv_online/",
        headers: { "Auth-Key": "secret-auth-key" },
      }),
    );

    expect(failure.code).toBe("unsupported-scheme");
    expect(String(failure.detail ?? "")).not.toContain("secret-auth-key");
  });

  it("refuses a cleartext PhishTank feed URL, and its refusal quotes no path", async () => {
    const failure = await failureOf(
      createNodePhishTankHttpClient({ classifyAddress: allowLoopback }).request({
        url: "http://127.0.0.1:1/data/secret-app-key/online-valid.csv",
        headers: { "User-Agent": "phishtank/tester" },
      }),
    );

    expect(failure.code).toBe("unsupported-scheme");
    // The app key IS the path, so the detail may name the protocol and nothing
    // else. This is the assertion that stands between a key and a log line.
    expect(failure.detail).toBe("http:");
    expect(String(failure.detail ?? "")).not.toContain("secret-app-key");
  });

  it("refuses a download URL carrying userinfo rather than transmitting it", async () => {
    const failure = await failureOf(
      urlhaus().request({
        url: "http://user:secret@127.0.0.1:1/downloads/csv_online/",
        headers: { "Auth-Key": "k" },
      }),
    );

    expect(failure.code).toBe("url-credentials");
    expect(failure.detail).toBeNull();
  });

  it("refuses a non-HTTP scheme", async () => {
    const failure = await failureOf(
      urlhaus().request({ url: "file:///etc/passwd", headers: {} }),
    );

    expect(failure.code).toBe("unsupported-scheme");
  });

  it("refuses an unparseable download URL without echoing it", async () => {
    const failure = await failureOf(
      phishtank().request({ url: "data/secret-app-key/online-valid.csv", headers: {} }),
    );

    expect(failure.code).toBe("invalid-url");
    expect(failure.detail).toBeNull();
  });

  /**
   * The header map is the one caller-influenced seam this engine has, and for
   * URLhaus it is where the credential lives. A CRLF in a value is request
   * splitting; it is refused before a socket opens, and the refusal names the
   * field but never its value.
   */
  it("refuses a header value carrying CRLF, without echoing the value", async () => {
    const failure = await failureOf(
      urlhaus().request({
        url: "https://urlhaus.example/downloads/csv_online/",
        headers: { "Auth-Key": "k\r\nX-Injected: 1" },
      }),
    );

    expect(failure.code).toBe("http-malformed");
    expect(failure.detail).toBe("invalid value for auth-key");
    expect(String(failure.detail ?? "")).not.toContain("X-Injected");
  });

  /**
   * `http.request` validates the whole header block synchronously, so a value
   * Node rejects but this client's own splitting guard does not — anything
   * outside Latin-1, for instance — throws before the request object exists and
   * cannot reach the `error` event. Without an explicit catch that raw
   * `TypeError` escapes the boundary untyped, carrying a Node-authored message
   * this client never inspected. It must arrive as one of ours instead.
   */
  it("types a header Node rejects synchronously rather than leaking a raw TypeError", async () => {
    const failure = await failureOf(
      urlhaus().request({
        url: "https://urlhaus.example/downloads/csv_online/",
        headers: { "Auth-Key": "kĀ" },
      }),
    );

    expect(failure.name).toBe("UrlhausHttpFailure");
    expect(failure.code).toBe("http-malformed");
    expect(failure.detail).toBe("invalid request header");
  });

  it("refuses a header NAME that is not an HTTP token", async () => {
    const failure = await failureOf(
      urlhaus().request({
        url: "https://urlhaus.example/downloads/csv_online/",
        headers: { "Auth Key": "k" },
      }),
    );

    expect(failure.code).toBe("http-malformed");
  });
});

/**
 * End to end: the SHIPPED updaters, driven by the SHIPPED clients, against a
 * loopback provider. This is the claim the issue was about — a caller can now
 * refresh a mirror with what the package provides — and it is the only test
 * here that exercises client and updater together.
 */
describe("mirror updaters over the real Node clients", () => {
  const clock = { now: () => new Date("2026-02-03T04:05:06.000Z") };

  it("updates a URLhaus snapshot end to end", async () => {
    let seenAuthKey: string | string[] | undefined;
    const port = await startServer((_path, headers) => {
      seenAuthKey = headers["auth-key"];
      return { status: 200, headers: { etag: '"v1"' }, body: URLHAUS_CSV };
    });

    let stored: UrlhausSnapshot | null = null;
    const store: UrlhausSnapshotStore = {
      readMetadata: (): Promise<UrlhausSnapshotMetadata | null> => Promise.resolve(null),
      replace: (snapshot): Promise<void> => {
        stored = snapshot;
        return Promise.resolve();
      },
    };

    const result = await updateUrlhausSnapshot({
      client: urlhaus(),
      store,
      credential: createOnlineSecret("real-auth-key"),
      clock,
      dumpUrl: `http://127.0.0.1:${port}/downloads/csv_online/`,
    });

    expect(result.status).toBe("updated");
    expect(seenAuthKey).toBe("real-auth-key");
    expect(stored).not.toBeNull();
    const snapshot = stored as unknown as UrlhausSnapshot;
    expect(snapshot.records).toHaveLength(1);
    expect(snapshot.records[0]?.url).toBe("http://malware.example/a.bin");
    expect(snapshot.metadata.etag).toBe('"v1"');
    expect(snapshot.metadata.observedAt).toBe("2026-02-03T04:05:06.000Z");
  });

  it("updates a PhishTank snapshot end to end, keeping the keyed URL out of metadata", async () => {
    let seenPath = "";
    const port = await startServer((path) => {
      seenPath = path;
      return { status: 200, headers: { etag: '"p1"' }, body: PHISHTANK_CSV };
    });

    let stored: PhishTankSnapshot | null = null;
    const store: PhishTankSnapshotStore = {
      readMetadata: (): Promise<PhishTankSnapshotMetadata | null> => Promise.resolve(null),
      replace: (snapshot): Promise<void> => {
        stored = snapshot;
        return Promise.resolve();
      },
    };

    const result = await updatePhishTankSnapshot({
      client: phishtank(),
      store,
      appKey: createOnlineSecret("real-app-key"),
      clock,
      baseUrl: `http://127.0.0.1:${port}/data`,
      userAgent: "phishtank/tester",
    });

    expect(result.status).toBe("updated");
    // The key reached the provider in the path, exactly once.
    expect(seenPath).toBe("/data/real-app-key/online-valid.csv");
    const snapshot = stored as unknown as PhishTankSnapshot;
    expect(snapshot.records).toHaveLength(1);
    expect(snapshot.records[0]?.phishId).toBe("9001");
    // ...and reached nothing else. The whole stored snapshot is searched.
    expect(JSON.stringify(snapshot)).not.toContain("real-app-key");
  });

  it("turns a transport failure into a typed updater cause that names no secret", async () => {
    const port = await deadLoopbackPort();
    const store: PhishTankSnapshotStore = {
      readMetadata: (): Promise<PhishTankSnapshotMetadata | null> => Promise.resolve(null),
      replace: (): Promise<void> => Promise.reject(new Error("must not be called")),
    };

    const result = await updatePhishTankSnapshot({
      client: phishtank(),
      store,
      appKey: createOnlineSecret("real-app-key"),
      clock,
      baseUrl: `http://127.0.0.1:${port}/data`,
    });

    expect(result.status).toBe("failure");
    const cause = (result as { cause: { code: string; message: string } }).cause;
    expect(cause.code).toBe("phishtank-network-error");
    expect(cause.message).toContain("PhishTankHttpFailure");
    expect(JSON.stringify(result)).not.toContain("real-app-key");
  });
});

/**
 * Properties of this engine that must outlive its redirect policy
 * (LINK-scectgty).
 *
 * Written BEFORE the engine learned to follow a redirect, and phrased so that
 * following one cannot make them pass vacuously: each asserts something about
 * what reached the wire and what reached a failure, not about how many requests
 * the engine chose to make. A feed download carries the caller's own
 * credential, so "where did the secret go" is the question these hold onto
 * while the hop policy around them moves.
 */
describe("mirror engine invariants that outlive its redirect policy", () => {
  /** Allows loopback exactly as {@link allowLoopback} does, and records every address it was asked about. */
  function recordingClassifier(): {
    readonly seen: string[];
    readonly classify: (address: string) => TransportAddressDecision;
  } {
    const seen: string[] = [];
    return {
      seen,
      classify: (address: string) => {
        seen.push(address);
        return allowLoopback(address);
      },
    };
  }

  interface SeenRequest {
    readonly host: string;
    readonly path: string;
    readonly authKey: string | string[] | undefined;
  }

  /**
   * A socket opens only to an address the policy classified. Half one: an
   * IP-LITERAL host, which `net.connect` resolves not at all, so the engine has
   * to classify it on its own path or the policy is simply skipped.
   */
  it("classifies an IP-LITERAL host before the socket opens", async () => {
    const recorder = recordingClassifier();
    const port = await startServer(() => ({ status: 200, body: URLHAUS_CSV }));

    const response = await createNodeUrlhausHttpClient({
      allowInsecureUrl: true,
      classifyAddress: recorder.classify,
    }).request({
      url: `http://127.0.0.1:${port}/downloads/csv_online/`,
      headers: { "Auth-Key": "k" },
    });

    expect(response.status).toBe(200);
    expect(recorder.seen).toContain("127.0.0.1");
  });

  /**
   * Half two: a NAME, whose addresses arrive from the resolver. `localhost` is
   * never an IP literal, so the only path that can populate the recorder is the
   * `dns.lookup` gate — the seam that has to hold per CONNECTION rather than
   * per request.
   */
  it("classifies a RESOLVED address before the socket opens", async () => {
    const recorder = recordingClassifier();
    const port = await startServer(() => ({ status: 200, body: URLHAUS_CSV }));

    await createNodeUrlhausHttpClient({
      allowInsecureUrl: true,
      classifyAddress: recorder.classify,
    })
      .request({ url: `http://localhost:${port}/x`, headers: { "Auth-Key": "k" } })
      // The outcome is not the claim: whichever family wins the connect, the
      // classifier must have been consulted with a resolved address first.
      .catch(() => null);

    expect(recorder.seen.some((address) => address === "127.0.0.1" || address === "::1")).toBe(
      true,
    );
  });

  /**
   * The credential reaches the origin the caller named, and no other origin
   * ever observes it.
   *
   * Both halves are asserted against what the SERVER saw, so the claim does not
   * depend on whether the engine follows the `302`: today nothing is sent to
   * the second origin at all; when a hop is followed, the request that arrives
   * there must still carry no `Auth-Key`. One loopback server answers both
   * origins, so the second one is a genuine HOST change (`localhost` against
   * `127.0.0.1`) rather than a second process.
   */
  it("reveals the Auth-Key to the named origin and to no other origin", async () => {
    const seen: SeenRequest[] = [];
    let port = 0;
    port = await startServer((path, headers) => {
      seen.push({ host: String(headers.host ?? ""), path, authKey: headers["auth-key"] });
      if (path === "/downloads/csv_online/") {
        return { status: 302, headers: { location: `http://localhost:${port}/elsewhere` } };
      }
      return { status: 200, body: URLHAUS_CSV };
    });

    await urlhaus()
      .request({
        url: `http://127.0.0.1:${port}/downloads/csv_online/`,
        headers: { "Auth-Key": "secret-auth-key" },
      })
      .catch(() => null);

    const named = seen.filter((request) => request.host.startsWith("127.0.0.1"));
    const elsewhere = seen.filter((request) => !request.host.startsWith("127.0.0.1"));
    // Revealed exactly once, to exactly the host the caller wrote down.
    expect(named).toHaveLength(1);
    expect(named[0]?.authKey).toBe("secret-auth-key");
    // And nowhere else — whether or not a request was made there at all.
    for (const request of elsewhere) {
      expect(request.authKey).toBeUndefined();
    }
  });

  /**
   * No typed failure carries a request path or a header value, whatever the
   * failure is. PhishTank's app key IS a path segment and URLhaus's key IS a
   * header value, so this is the assertion standing between a caller's
   * credential and a log line. Swept across the failure modes a bad download
   * URL can actually produce rather than pinned one at a time, because the rule
   * belongs to the mapper and not to any one code.
   */
  it("never puts a URL path or a header value into a failure", async () => {
    const key = "secret-app-key";
    const auth = "secret-auth-key";
    // Deferred, so a failing assertion cannot leave the remaining rejections
    // unobserved and turn one red test into a run-level unhandled error.
    const attempts: readonly (() => Promise<unknown>)[] = [
      // Cleartext under the SHIPPED policy: the detail may name the scheme.
      () =>
        createNodePhishTankHttpClient({ classifyAddress: allowLoopback }).request({
          url: `http://data.phishtank.example/data/${key}/online-valid.csv`,
          headers: { "User-Agent": "phishtank/tester" },
        }),
      // A scheme no seam covers.
      () =>
        phishtank().request({
          url: `ftp://data.phishtank.example/data/${key}/online-valid.csv`,
          headers: {},
        }),
      // Userinfo, which is refused rather than dropped.
      () =>
        phishtank().request({
          url: `https://user:${auth}@data.phishtank.example/data/${key}/online-valid.csv`,
          headers: {},
        }),
      // Unparseable, so nothing about it may be echoed.
      () => phishtank().request({ url: `data/${key}/online-valid.csv`, headers: {} }),
      // Request splitting, refused before a socket opens.
      () =>
        urlhaus().request({
          url: "https://urlhaus.example/downloads/csv_online/",
          headers: { "Auth-Key": `${auth}\r\nX-Injected: 1` },
        }),
    ];

    for (const attempt of attempts) {
      const failure = await failureOf(attempt());
      const rendered = JSON.stringify({
        code: failure.code,
        detail: failure.detail,
        message: (failure as { message?: unknown }).message,
      });
      expect(rendered).not.toContain(key);
      expect(rendered).not.toContain(auth);
      expect(rendered).not.toContain("online-valid.csv");
    }
  });
});
