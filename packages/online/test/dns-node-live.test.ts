/**
 * Live coverage for the concrete `node:dns` DNS resolver port (LINK-kfillkxk).
 *
 * Every other DNS test injects a fake {@link DnsResolverPort} or builds answers
 * from tuples it supplies itself, so `createNodeDnsResolver` was composed in no
 * test, no feature and no tool — and shipped inverting a signal. c-ares renders
 * the DNS root label as the EMPTY STRING, the port copied it raw, and the
 * normalizer's `isNullMx` matches `"."` exactly, so a domain publishing RFC 7505
 * "I accept no mail at all" was reported as `explicit-mx`.
 *
 * Uses a loopback DNS server, so it needs no external network — which also lets
 * it put the root label on the wire as the single zero byte a real authoritative
 * server sends, rather than assuming what c-ares hands back. The first test pins
 * that assumption against a bare `Resolver`, so the mapping this file exercises
 * can never become a test of its own premise.
 */
import { createSocket, type Socket } from "node:dgram";
import { Resolver } from "node:dns/promises";
import { afterEach, describe, expect, it } from "vitest";

import { createNodeDnsResolver } from "../src/reputation/dns-node.js";
import { normalizeDnsState, type DnsAnswer } from "../src/reputation/index.js";

let socket: Socket | undefined;

afterEach(async () => {
  const running = socket;
  socket = undefined;
  if (running === undefined) return;
  await new Promise<void>((resolve) => running.close(() => resolve()));
});

/** Walk past a QNAME, honoring a compression pointer, and return the next offset. */
function endOfQname(message: Buffer, start: number): number {
  let offset = start;
  while (offset < message.length) {
    const length = message[offset]!;
    if (length === 0) return offset + 1;
    if ((length & 0xc0) === 0xc0) return offset + 2;
    offset += 1 + length;
  }
  return offset;
}

/** Encode a domain name as DNS wire-format labels. The root is a single 0 byte. */
function encodeName(name: string): Buffer {
  if (name === "." || name === "") return Buffer.from([0x00]);
  const labels = name.replace(/\.$/, "").split(".");
  return Buffer.concat([
    ...labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, "ascii")])),
    Buffer.from([0x00]),
  ]);
}

/**
 * Stand up a loopback DNS server answering every MX query with one record whose
 * target is `exchange`, and return its port. `"."` is written to the wire as the
 * root label, which is exactly the shape RFC 7505 defines.
 */
async function startMxServer(exchange: string, preference = 0): Promise<number> {
  const created = createSocket("udp4");
  socket = created;

  created.on("message", (message, remote) => {
    const questionEnd = endOfQname(message, 12) + 4;
    const header = Buffer.alloc(12);
    message.copy(header, 0, 0, 2); // echo the query ID
    header.writeUInt16BE(0x8580, 2); // QR + AA + RD + RA, RCODE 0
    header.writeUInt16BE(1, 4); // QDCOUNT
    header.writeUInt16BE(1, 6); // ANCOUNT

    const target = encodeName(exchange);
    const rdata = Buffer.concat([Buffer.alloc(2), target]);
    rdata.writeUInt16BE(preference, 0);

    const answer = Buffer.alloc(12 + rdata.length);
    answer.writeUInt16BE(0xc00c, 0); // NAME: pointer to the question at offset 12
    answer.writeUInt16BE(15, 2); // TYPE MX
    answer.writeUInt16BE(1, 4); // CLASS IN
    answer.writeUInt32BE(300, 6); // TTL
    answer.writeUInt16BE(rdata.length, 10);
    rdata.copy(answer, 12);

    created.send(Buffer.concat([header, message.subarray(12, questionEnd), answer]), remote.port, remote.address);
  });

  await new Promise<void>((resolve) => created.bind(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (typeof address === "string") throw new Error("no port");
  return address.port;
}

const OBS = { observedAt: "2026-08-24T00:00:00.000Z", resolver: "test" } as const;
const NODATA = (type: "A" | "AAAA" | "NS"): DnsAnswer =>
  ({ type, state: "nodata", observation: OBS }) as DnsAnswer;

/** Derive mail semantics the way the enricher does, from the port's own answer. */
function mailSemanticFor(mx: DnsAnswer): string {
  return normalizeDnsState({
    host: "nomail.example",
    zone: "example",
    a: NODATA("A"),
    aaaa: NODATA("AAAA"),
    ns: NODATA("NS"),
    mx,
  }).mailSemantic;
}

describe("createNodeDnsResolver (live)", () => {
  it("confirms the premise: c-ares renders a wire root label as the empty string", async () => {
    // Not a test of our code — a test of the assumption our mapping exists for.
    // If node ever starts returning ".", this fails and the mapping's comment in
    // dns-node.ts stops being true.
    const port = await startMxServer(".");
    const resolver = new Resolver();
    resolver.setServers([`127.0.0.1:${port}`]);

    expect(await resolver.resolveMx("nomail.example")).toEqual([{ exchange: "", priority: 0, type: "MX" }]);
  });

  it("reports an RFC 7505 null MX with the documented '.' exchange", async () => {
    const port = await startMxServer(".");
    const answer = await createNodeDnsResolver({ servers: [`127.0.0.1:${port}`] }).query({
      name: "nomail.example",
      type: "MX",
    });

    expect(answer.state).toBe("ok");
    if (answer.state !== "ok" || answer.type !== "MX") throw new Error("expected an ok MX answer");
    expect(answer.exchanges).toEqual([{ exchange: ".", preference: 0, ttlSeconds: -1 }]);
  });

  it("carries a live null MX through to mailSemantic 'null-mx'", async () => {
    // The whole point of the fix: null-mx was unreachable outside fixtures.
    const port = await startMxServer(".");
    const answer = await createNodeDnsResolver({ servers: [`127.0.0.1:${port}`] }).query({
      name: "nomail.example",
      type: "MX",
    });

    expect(mailSemanticFor(answer)).toBe("null-mx");
  });

  it("leaves an ordinary exchange untouched and still reports explicit-mx", async () => {
    // The mapping must rewrite the root label and nothing else.
    const port = await startMxServer("mail.example.com", 10);
    const answer = await createNodeDnsResolver({ servers: [`127.0.0.1:${port}`] }).query({
      name: "example.com",
      type: "MX",
    });

    if (answer.state !== "ok" || answer.type !== "MX") throw new Error("expected an ok MX answer");
    expect(answer.exchanges).toEqual([{ exchange: "mail.example.com", preference: 10, ttlSeconds: -1 }]);
    expect(mailSemanticFor(answer)).toBe("explicit-mx");
  });

  /**
   * Malformed names, answered locally (LINK-enbiprjm).
   *
   * No external network and no loopback server: c-ares rejects both of these
   * before a packet leaves the host, which is the whole point — the answer must
   * not be an authoritative claim about a name that was never queried.
   */
  it("answers an empty name as invalid-name without querying", async () => {
    const answer = await createNodeDnsResolver().query({ name: "", type: "A" });

    expect(answer.state).toBe("invalid-name");
    // The regression: c-ares reports ENODATA here, which used to be taken at
    // face value as "this name authoritatively has no records".
    expect(answer.state).not.toBe("nodata");
  });

  it("answers a syntactically malformed name as invalid-name", async () => {
    // An empty label is rejected by c-ares as EBADNAME, locally.
    const answer = await createNodeDnsResolver().query({ name: "bad..dots", type: "A" });

    expect(answer.state).toBe("invalid-name");
  });

  it("records the configured resolver name on the observation", async () => {
    const port = await startMxServer(".");
    const answer = await createNodeDnsResolver({
      servers: [`127.0.0.1:${port}`],
      resolverName: "loopback-test",
    }).query({ name: "nomail.example", type: "MX" });

    expect(answer.observation.resolver).toBe("loopback-test");
  });
});
