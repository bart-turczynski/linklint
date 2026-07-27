/**
 * Live coverage for `NodeResolver` — the real `node:dns` path behind address
 * pinning (LINK-cubfsqmr).
 *
 * Like the rest of `transport/node.ts`, this had no behavioral coverage: every
 * other test injects a fixture resolver, so the concrete `lookup()` call and
 * its `systemErrorCode` mapping were unexecuted.
 *
 * No external network. `localhost` is answered from the hosts file, and the
 * negative cases use syntactically invalid hostnames, which getaddrinfo rejects
 * locally rather than putting a query on the wire. A name under `.invalid`
 * would be more idiomatic but can reach an upstream resolver, which would make
 * this suite fail on an offline machine.
 */
import { lookup } from "node:dns/promises";
import { describe, expect, it } from "vitest";

import { NodeResolver, systemErrorCode } from "../src/transport/node-resolver.js";

/** Capture the transport cause code for a resolve expected to fail. */
async function resolveFailure(hostname: string): Promise<string> {
  try {
    await new NodeResolver().resolve({ hostname });
    throw new Error("expected resolution to fail");
  } catch (error) {
    if (error instanceof Error && error.name === "NodeResolverFailure") {
      return (error as Error & { code: string }).code;
    }
    throw error;
  }
}

describe("NodeResolver (live)", () => {
  it("resolves loopback from the hosts file and normalizes the answer shape", async () => {
    const answers = await new NodeResolver().resolve({ hostname: "localhost" });

    expect(answers.length).toBeGreaterThan(0);
    for (const answer of answers) {
      expect([4, 6]).toContain(answer.family);
      expect(answer.ttlSeconds).toBe(0);
      expect(typeof answer.address).toBe("string");
    }
    // Whatever the host is configured with, every answer must be loopback —
    // this is the resolution the pinning layer will bind the socket to.
    const addresses = answers.map((a) => a.address);
    expect(addresses.every((a) => a === "127.0.0.1" || a === "::1")).toBe(true);
  });

  it("preserves resolver order rather than re-sorting by family", async () => {
    // `verbatim: true` is load-bearing: re-ordering would silently change which
    // address gets pinned, and the pinned address is the security-relevant one.
    // Asserting a specific order would encode this machine's hosts file, so
    // compare against a verbatim lookup instead — that pins the flag itself
    // without depending on what the host happens to return.
    const answers = await new NodeResolver().resolve({ hostname: "localhost" });
    const verbatim = await lookup("localhost", { all: true, verbatim: true });

    expect(answers.map((a) => a.address)).toEqual(verbatim.map((a) => a.address));
  });

  it("maps an unresolvable name to dns-not-found", async () => {
    expect(await resolveFailure("not a valid hostname")).toBe("dns-not-found");
  });

  it("rejects before resolving when the signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      new NodeResolver().resolve({ hostname: "localhost", signal: controller.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("rejects when the signal aborts during resolution", async () => {
    const controller = new AbortController();
    const pending = new NodeResolver().resolve({
      hostname: "localhost",
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("systemErrorCode", () => {
  it("reads the code off a real system error", async () => {
    // Drive a genuine getaddrinfo failure rather than a hand-built object, so
    // the mapper is checked against the shape Node actually throws.
    const error = await lookup("not a valid hostname", { all: true }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).not.toBeNull();
    expect(systemErrorCode(error)).toBe("ENOTFOUND");
  });

  it("returns null for values carrying no code", () => {
    expect(systemErrorCode(new Error("plain"))).toBeNull();
    expect(systemErrorCode(null)).toBeNull();
    expect(systemErrorCode("ENOTFOUND")).toBeNull();
  });
});
