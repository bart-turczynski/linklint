/**
 * Live coverage for the concrete Node RDAP HTTP client (LINK-mkddydzr).
 *
 * Every other RDAP test injects a fake {@link RdapHttpClient}, so the real
 * socket, header, decode and address-policy wiring would otherwise have no
 * behavioral coverage at all — which is exactly how the enricher shipped with no
 * runnable client behind it.
 *
 * Uses a loopback server, so it needs no external network. The real address
 * policy correctly refuses loopback, so most cases inject a permissive
 * classifier; the refusal itself is proved separately against the DEFAULT
 * policy, which is what keeps the permissive seam from being a silent hole.
 */
import { createServer, type Server } from "node:http";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { createNodeRdapHttpClient } from "../src/reputation/rdap-node.js";
import type { NodeRdapHttpClientOptions } from "../src/reputation/rdap-node.js";
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
 * The test seam: loopback is the only address a hermetic server can bind, and
 * the shipped policy refuses it. Everything else about the classifier's shape is
 * preserved so the client's own handling is what is under test.
 */
function allowLoopback(address: string): TransportAddressDecision {
  return { address, family: address.includes(":") ? 6 : 4, allowed: true, category: null };
}

function client(options: Omit<NodeRdapHttpClientOptions, "classifyAddress"> = {}) {
  return createNodeRdapHttpClient({ ...options, classifyAddress: allowLoopback });
}

async function failureOf(promise: Promise<unknown>): Promise<{ name?: unknown; code?: unknown }> {
  const error = await promise.then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(error).not.toBeNull();
  return error as { name?: unknown; code?: unknown };
}

describe("node RDAP HTTP client (live loopback)", () => {
  it("returns a decoded JSON body, and sends no credential", async () => {
    let seenPath = "";
    let seenHeaders: Record<string, string | string[] | undefined> = {};
    const port = await startServer((path, headers) => {
      seenPath = path;
      seenHeaders = headers;
      return {
        status: 200,
        headers: { "content-type": "application/rdap+json" },
        body: JSON.stringify({ ldhName: "example.com" }),
      };
    });

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/example.com`,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ ldhName: "example.com" });
    expect(response.headers["content-type"]).toBe("application/rdap+json");
    expect(seenPath).toBe("/domain/example.com");
    expect(seenHeaders.accept).toContain("application/rdap+json");
    // The descriptor declares `credentials: { kind: "none" }`. There is nothing
    // to send, so nothing that could carry one may appear.
    expect(seenHeaders.authorization).toBeUndefined();
    expect(seenHeaders.cookie).toBeUndefined();
    expect(seenHeaders["user-agent"]).toBeUndefined();
  });

  it("sends a User-Agent only when the caller supplies one", async () => {
    let seenAgent: string | string[] | undefined;
    const port = await startServer((_path, headers) => {
      seenAgent = headers["user-agent"];
      return { status: 200, body: "{}" };
    });

    await client({ userAgent: "linklint-test/1" }).request({
      url: `http://127.0.0.1:${port}/domain/example.com`,
    });

    expect(seenAgent).toBe("linklint-test/1");
  });

  it("decodes a gzip-encoded body", async () => {
    const payload = JSON.stringify({ ldhName: "gzipped.example", events: [] });
    const port = await startServer(() => ({
      status: 200,
      headers: { "content-encoding": "gzip", "content-type": "application/rdap+json" },
      body: gzipSync(Buffer.from(payload, "utf8")),
    }));

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/gzipped.example`,
    });

    expect(response.status).toBe(200);
    expect(response.body).toBe(payload);
  });

  /**
   * LINK-syeupoav: a 204 — or an empty error body served with a stale encoding
   * header — is an ordinary response here, not a decompression failure.
   *
   * These two cases originally passed because this client carried its own
   * zero-byte guard, working around `decodeResponseBody` handing an empty
   * buffer to zlib. That guard is gone: the shared decoder now answers an empty
   * body with an empty body, so these assertions pin the real path rather than
   * a local compensation.
   */
  it("returns an empty body rather than a decode failure when a Content-Encoding header is present", async () => {
    const port = await startServer(() => ({
      status: 204,
      headers: { "content-encoding": "gzip" },
    }));

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/empty.example`,
    });

    expect(response.status).toBe(204);
    expect(response.body).toBe("");
  });

  it("returns an empty 200 body served with a Content-Encoding header", async () => {
    const port = await startServer(() => ({
      status: 200,
      headers: { "content-encoding": "gzip", "content-length": "0" },
    }));

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/empty200.example`,
    });

    expect(response.status).toBe(200);
    expect(response.body).toBe("");
  });

  it("returns a 404 as an ordinary response, not a failure", async () => {
    const port = await startServer(() => ({
      status: 404,
      headers: { "content-type": "application/rdap+json" },
      body: JSON.stringify({ errorCode: 404 }),
    }));

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/missing.example`,
    });

    expect(response.status).toBe(404);
    expect(JSON.parse(response.body)).toEqual({ errorCode: 404 });
  });

  /** The redirect chain is `fetchRdapDomain`'s; this client performs ONE request. */
  it("returns a 3xx with its Location header without following it", async () => {
    const paths: string[] = [];
    const port = await startServer((path) => {
      paths.push(path);
      if (path === "/domain/moved.example") {
        return { status: 302, headers: { location: "/domain/target.example" } };
      }
      return { status: 200, body: JSON.stringify({ ldhName: "target.example" }) };
    });

    const response = await client().request({
      url: `http://127.0.0.1:${port}/domain/moved.example`,
    });

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe("/domain/target.example");
    expect(paths).toEqual(["/domain/moved.example"]);
  });

  it("reports a refused connection as a typed failure", async () => {
    const port = await deadLoopbackPort();

    const failure = await failureOf(
      client().request({ url: `http://127.0.0.1:${port}/domain/example.com` }),
    );

    expect(failure.name).toBe("RdapHttpFailure");
    expect(failure.code).toBe("connect-refused");
  });

  it("reports a caller abort as an AbortError", async () => {
    const controller = new AbortController();
    const port = await startServer(
      () =>
        new Promise<Reply>(() => {
          // Never replies; the abort is the only way out.
          controller.abort();
        }),
    );

    const failure = await failureOf(
      client().request({
        url: `http://127.0.0.1:${port}/domain/slow.example`,
        signal: controller.signal,
      }),
    );

    expect(failure.name).toBe("AbortError");
  });

  it("refuses a request aborted before it starts", async () => {
    const controller = new AbortController();
    controller.abort();

    const failure = await failureOf(
      client().request({ url: "http://127.0.0.1:1/domain/example.com", signal: controller.signal }),
    );

    expect(failure.name).toBe("AbortError");
  });

  /**
   * The control for every permissive-classifier case above: the SHIPPED policy —
   * the same table L0 pins destinations with — refuses loopback, so a poisoned
   * bootstrap entry naming private space never reaches a socket.
   */
  it("refuses a prohibited IP-LITERAL address under the default policy, before connecting", async () => {
    // `net.connect` skips DNS entirely for a literal host, so the lookup gate
    // never sees this URL — the literal has to be classified on its own path or
    // a bootstrap entry written as a bare address walks past the policy.
    let reached = false;
    const port = await startServer(() => {
      reached = true;
      return { status: 200, body: "{}" };
    });

    const failure = await failureOf(
      createNodeRdapHttpClient().request({
        url: `http://127.0.0.1:${port}/domain/example.com`,
      }),
    );

    expect(failure.name).toBe("RdapHttpFailure");
    expect(failure.code).toBe("prohibited-address");
    expect(reached).toBe(false);
  });

  it("refuses a prohibited RESOLVED address under the default policy, before connecting", async () => {
    // The other half of the gate: a hostname whose answers are prohibited. The
    // classification happens inside the `dns.lookup` replacement, so Node only
    // ever receives answers that passed.
    let reached = false;
    const port = await startServer(() => {
      reached = true;
      return { status: 200, body: "{}" };
    });

    const failure = await failureOf(
      createNodeRdapHttpClient().request({
        url: `http://localhost:${port}/domain/example.com`,
      }),
    );

    expect(failure.name).toBe("RdapHttpFailure");
    expect(failure.code).toBe("prohibited-address");
    expect(reached).toBe(false);
  });

  it("refuses a provider URL carrying userinfo rather than transmitting it", async () => {
    const failure = await failureOf(
      client().request({ url: "http://user:secret@127.0.0.1:1/domain/example.com" }),
    );

    expect(failure.code).toBe("url-credentials");
    expect(String((failure as { detail?: unknown }).detail ?? "")).not.toContain("secret");
  });

  it("refuses a non-HTTP scheme", async () => {
    const failure = await failureOf(client().request({ url: "file:///etc/passwd" }));

    expect(failure.code).toBe("unsupported-scheme");
  });

  it("stops an oversized body at the configured budget", async () => {
    const port = await startServer(() => ({
      status: 200,
      body: "x".repeat(4_096),
    }));

    const failure = await failureOf(
      client({ policy: { maxResponseBytes: 512 } }).request({
        url: `http://127.0.0.1:${port}/domain/big.example`,
      }),
    );

    expect(failure.code).toBe("response-too-large");
  });

  it("accepts a body that fits the configured budget", async () => {
    // Guards against a vacuous pass above: the same shape under a budget it fits
    // must still complete.
    const port = await startServer(() => ({ status: 200, body: "x".repeat(4_096) }));

    const response = await client({ policy: { maxResponseBytes: 8_192 } }).request({
      url: `http://127.0.0.1:${port}/domain/big.example`,
    });

    expect(response.status).toBe(200);
    expect(response.body.length).toBe(4_096);
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
      client({ policy: { maxResponseHeaderBytes: 512 } }).request({
        url: `http://127.0.0.1:${port}/domain/head.example`,
      }),
    );

    expect(failure.code).toBe("response-headers-too-large");
  });
});
