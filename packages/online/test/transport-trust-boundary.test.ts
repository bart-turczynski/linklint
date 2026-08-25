/**
 * LINK-zzaerxod — the trust boundary at the HTTP port seam.
 *
 * `SafeSession.execute()` pins one address, verifies the connector's reported
 * peer against it, and then hands the HTTP port a bare `connectionId` string.
 * `HttpResponse` carries a status, headers and a body and NO evidence of which
 * socket produced them, so the transport cannot re-check that the response came
 * off the pinned socket the way it re-checks `TransportConnection.remoteAddress`
 * at connect time. The built-in composition closes that gap STRUCTURALLY rather
 * than by protocol: `NodeConnectionPorts` implements `ConnectorPort` and
 * `HttpPort` together, owns the socket map, and `createNodeSafeTransport()`
 * passes ONE instance as both — so the binding between the pinned socket and the
 * request written onto it is object identity.
 *
 * Two things are pinned here, and nothing held either of them before:
 *
 *   1. IDENTITY — that `createNodeSafeTransport()` really does pass the same
 *      object as `connector` and `http`. Two `NodeConnectionPorts` instances
 *      would type-check, wire up, and quietly separate the socket map that
 *      opened the pinned connection from the one that writes the request.
 *   2. THE PROSE — that `docs/safe-transport.md` and `docs/guarantees.md` name
 *      a caller-supplied port as a trusted capability, and that F6/F7 carry the
 *      scope note that identity pin is the evidence for. A guarantee register
 *      whose qualification can be deleted without failing anything is the exact
 *      failure mode the register exists to prevent.
 *
 * The doc assertions run over FLATTENED text. A raw substring silently matches
 * nothing the moment the sentence hard-wraps, and blockquote `> ` markers
 * survive a naive flatten — `flattenMarkdown` is exercised on both traps below
 * so these assertions cannot pass vacuously.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import type { CreateSafeTransportOptions } from "../src/transport/safe-transport.js";

const captured = vi.hoisted(() => ({
  options: undefined as CreateSafeTransportOptions | undefined,
  calls: 0,
}));

vi.mock("../src/transport/safe-transport.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/transport/safe-transport.js")>();
  return {
    ...actual,
    createSafeTransport: (options: CreateSafeTransportOptions) => {
      captured.options = options;
      captured.calls += 1;
      return actual.createSafeTransport(options);
    },
  };
});

const { createNodeSafeTransport, NodeConnectionPorts } = await import("../src/transport/node.js");

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(packageRoot, "..", "..");

/**
 * Markdown as one line of text. Hard wraps become single spaces so a substring
 * assertion survives reflowing, and a leading blockquote marker is stripped PER
 * LINE, before the join — a `> ` in the middle of the joined string would
 * otherwise break every quoted claim.
 */
function flattenMarkdown(markdown: string): string {
  return markdown
    .split("\n")
    .map((line) => line.replace(/^\s*>\s?/, "").trim())
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

const safeTransportDoc = flattenMarkdown(
  readFileSync(join(repoRoot, "docs", "safe-transport.md"), "utf8"),
);
const register = flattenMarkdown(readFileSync(join(repoRoot, "docs", "guarantees.md"), "utf8"));

describe("flattenMarkdown (anti-vacuity)", () => {
  it("joins a hard-wrapped sentence into one matchable line", () => {
    expect(flattenMarkdown("a caller-supplied connector\nor HTTP port is a\ntrusted capability")).toBe(
      "a caller-supplied connector or HTTP port is a trusted capability",
    );
  });

  it("strips a blockquote marker from every line, not just the first", () => {
    expect(flattenMarkdown("> trusted\n> capability\n>\n> not sandboxed")).toBe(
      "trusted capability not sandboxed",
    );
  });

  it("reads non-empty documents (a missing file must fail, not pass silently)", () => {
    expect(safeTransportDoc.length).toBeGreaterThan(4_000);
    expect(register.length).toBeGreaterThan(4_000);
    // Control phrases that predate this unit: if these stop matching, the
    // helper broke rather than the claims below being newly true.
    expect(safeTransportDoc).toContain("The safe transport is the only built-in connection boundary");
    expect(register).toContain("F11 is a closure claim, not a completeness one.");
  });
});

describe("the built-in composition binds the pinned socket by object identity", () => {
  it("passes ONE NodeConnectionPorts instance as both connector and http", () => {
    captured.options = undefined;
    captured.calls = 0;

    createNodeSafeTransport();

    expect(captured.calls, "createNodeSafeTransport must build through createSafeTransport").toBe(1);
    const options = captured.options;
    expect(options).toBeDefined();
    expect(
      options?.connector,
      "the connector that opened the pinned socket and the HTTP port that writes " +
        "the request onto it must be the SAME object — the transport hands the " +
        "port only a connectionId string and can never re-check the binding itself",
    ).toBe(options?.http);
  });

  it("that one object is the socket-owning adapter, not an unrelated pair that happens to match", () => {
    captured.options = undefined;
    createNodeSafeTransport();

    const network = captured.options?.connector;
    expect(network).toBeInstanceOf(NodeConnectionPorts);
    // Both halves of the capability live on the same instance: this is what
    // makes `connector === http` meaningful rather than incidental.
    expect(typeof (network as NodeConnectionPorts).connect).toBe("function");
    expect(typeof (network as NodeConnectionPorts).request).toBe("function");
    expect(typeof (network as NodeConnectionPorts).close).toBe("function");
  });

  it("gives each transport its own instance, so one session's socket map is not another's", () => {
    captured.options = undefined;
    createNodeSafeTransport();
    const first = captured.options?.connector;

    captured.options = undefined;
    createNodeSafeTransport();
    const second = captured.options?.connector;

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first).not.toBe(second);
  });
});

describe("docs/safe-transport.md names a caller-supplied port a trusted capability", () => {
  it.each([
    "A caller-supplied connector or HTTP port is a **trusted capability**",
    "the obligation to use that exact connection",
    "passes one `NodeConnectionPorts` instance as both the connector and the HTTP port",
    "the binding is object identity",
  ])("states %j", (phrase) => {
    expect(safeTransportDoc).toContain(phrase);
  });

  it("records the shape a future API break would take, so a rename is not mistaken for one", () => {
    expect(safeTransportDoc).toContain(
      "merging `ConnectorPort` and `HttpPort` into a single connection capability",
    );
  });
});

describe("docs/guarantees.md scopes F6 and F7 and leaves F11 alone", () => {
  it("carries the scope note naming the identity pin as its evidence", () => {
    expect(register).toContain(
      "**F6 and F7 are scoped to this boundary and to the built-in composition",
    );
    expect(register).toContain("packages/online/test/transport-trust-boundary.test.ts");
  });

  it("says why F11 is deliberately not qualified with them", () => {
    expect(register).toContain(
      "F11 is deliberately left unqualified: it is a closure claim about what the " +
        "transport hands the connector",
    );
  });

  it("keeps F6 and F7 pinned by the generic composition, not narrowed to the built-in one", () => {
    // The cited tests construct via `createSafeTransport` with INJECTED fixture
    // ports. Narrowing the rows to `createNodeSafeTransport` would make the
    // register LESS accurate than the code and orphan those tests.
    const suite = readFileSync(join(packageRoot, "test", "safe-transport.test.ts"), "utf8");
    expect(suite).toContain("createSafeTransport({");
    expect(suite).toContain("TransportFixtureHarness");
    expect(register).toContain("| F6 | Redirects are returned to the caller and never followed");
    expect(register).toContain("| F7 | Ambient credential headers are never copied to a destination");
  });
});

describe("the obligation is stated where an implementer meets it", () => {
  const types = readFileSync(join(packageRoot, "src", "transport", "types.ts"), "utf8");

  it.each([
    "must write this request onto THAT",
    "and no other",
    "return a redirect response as-is",
    "no cookie jar, ambient",
  ])("HttpPort/connectionId TSDoc states %j", (phrase) => {
    expect(types).toContain(phrase);
  });

  it("keeps the precedent it follows — the observed-peer obligation on TransportConnection", () => {
    expect(types).toContain("The peer address the socket OBSERVED");
  });
});
