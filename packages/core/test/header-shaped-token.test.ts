import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";

// LINK-dyqyhtgo (T2.4) — COMMIT 2 of 2. The previous commit pinned this gap
// OPEN: each payload below returned 0.00/info with an EMPTY reason list, which
// under docs/architecture.md §1.1's fourth rule asserts "there is nothing to say
// about this URL". The diff of this file carries the before and the after.
//
// James Kettle's 2022 response-queue-poisoning work is the strongest case a URL
// linter gets, because the disclosed payload is entirely a URL. RFC 9112 §3
// fixes the request line as `method SP request-target SP HTTP-version CRLF`,
// and RFC 3986 §2.1 requires a space inside a URI to be percent-encoded
// precisely because it is that delimiter — so `%20HTTP/1.1` in a request target
// reads as one target and becomes two lines to anything that re-emits it
// undecoded.
//
// `control_char` (0.60) covers the neighbouring shape and is excluded from this
// one deliberately: docs/reason-codes.md states that "an encoded **space**
// (`%20`) is not a control character and never flags" there. The exclusion is
// asserted on every payload row below, because it is the reason this code
// exists rather than an accident of ordering.
//
// The CONTROLS section is the false-positive profile and did NOT change across
// the two commits. It is what shows the gate is on the COMBINATION — a token
// plus a percent-encoded wire separator plus, for a field line, a value from
// that field's own grammar — rather than on the bare token.

/** The two URLs the gap matrix quotes verbatim, plus the rest of the family. */
const PAYLOADS: ReadonlyArray<readonly [string, string]> = [
  ["https://example.com/?x=Host:%20evil.com", "gap-matrix row: Host field line in a query value"],
  ["https://example.com/a%20HTTP/1.1", "gap-matrix row: request-line shape in the path"],
  ["https://example.com/?x=Transfer-Encoding:%20chunked", "the TE field line that desyncs"],
  ["https://example.com/?x=Content-Length:%200", "the CL field line that desyncs"],
  ["https://example.com/?x=Expect:%20100-continue", "Expect: 100-continue field line"],
];

/**
 * Benign rows that stay quiet. Each carries a header-shaped token WITHOUT the
 * encoded wire separator that would put it in request-line or field-line
 * position, or with a value outside the field's own grammar — a docs search, a
 * blog slug, an event listing.
 */
const CONTROLS: ReadonlyArray<readonly [string, string]> = [
  ["https://example.com/?q=Host:", "bare token, no encoded separator — the docs-search shape"],
  ["https://example.com/?q=HTTP/1.1", "bare version token with no encoded SP in front of it"],
  [
    "https://example.com/?q=Transfer-Encoding%3A+chunked",
    "a form encoder writes `+` for SP and `%3A` for the colon",
  ],
  ["https://example.com/blog/host-header-attacks", "an article slug about the attack"],
  ["https://example.com/docs/http/1.1/host-header", "a documentation path"],
  [
    "https://example.com/?title=Expect:%20the%20unexpected",
    "encoded SP after the token, but the value is outside the Expect grammar",
  ],
  [
    "https://example.com/?owner=Host:%20John%20Smith",
    "encoded SP after the token, but the value is not host-shaped",
  ],
];

describe("header-shaped tokens in path/query are detected (LINK-dyqyhtgo)", () => {
  it.each(PAYLOADS)("%s (%s) reaches 0.50/medium on this code alone", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0.5);
    expect(r.severity).toBe("medium");
    expect(r.reasons.map((x) => x.code)).toEqual(["header_shaped_token"]);
  });

  it("control_char stays out of it — %20 is excluded from that code by design", () => {
    for (const [url] of PAYLOADS) {
      const codes = inspect(url).reasons.map((x) => x.code);
      expect(codes).not.toContain("control_char");
    }
  });

  it("the detail names the wire shape that fired, not just the token", () => {
    const reqLine = inspect("https://example.com/a%20HTTP/1.1").reasons[0]!;
    expect(reqLine.detail).toContain("request-line shape");
    const hostLine = inspect("https://example.com/?x=Host:%20evil.com").reasons[0]!;
    expect(hostLine.detail).toContain("'host:'");
    expect(hostLine.detail).toContain("host-shaped value");
  });

  it("registers at weight 0.50 as a scoring lexical code", () => {
    expect(REASON_CODES.header_shaped_token).toMatchObject({
      layer: "lexical",
      scoring: true,
      weight: 0.5,
    });
  });
});

describe("the encoded-CRLF neighbour composes rather than being replaced", () => {
  // Re-derived rather than trusted. An encoded CRLF in the path or query was
  // already `control_char` at 0.60 with `encoding_obfuscation` alongside it, so
  // this code is additive on that row rather than the thing that finds it — and
  // it adds what a byte scan has no way to say: which header the line declares.
  it("an encoded CRLF payload keeps control_char and gains this code", () => {
    const r = inspect("https://example.com/?x=Host:%20evil.com%0d%0a");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("control_char");
    expect(codes).toContain("header_shaped_token");
    // 0.74 -> 0.87: the row was already `high` on control_char +
    // encoding_obfuscation; this code stacks onto it rather than replacing it.
    expect(r.severity).toBe("critical");
  });

  it("the full Kettle-shaped payload stacks to critical", () => {
    const r = inspect("https://example.com/%20HTTP/1.1%0d%0aHost:%20evil.com");
    expect(r.severity).toBe("critical");
    expect(r.reasons.map((x) => x.code)).toContain("header_shaped_token");
  });

  it("an encoded line break in front of a field name fires without a value grammar", () => {
    // Arm 3: here the encoded CRLF is the second signal, so `Host:` needs no
    // host-shaped value behind it.
    const detail = inspect("https://example.com/?x=%0d%0aHost:anything").reasons.find(
      (r) => r.code === "header_shaped_token",
    )?.detail;
    expect(detail).toContain("encoded line break");
  });
});

describe("benign header-shaped text stays quiet (false-positive controls)", () => {
  it.each(CONTROLS)("%s (%s) raises no header-shaped-token finding", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).not.toContain("header_shaped_token");
  });

  it("a fragment is out of scope — it is stripped before a request target exists", () => {
    const codes = inspect("https://example.com/#%20HTTP/1.1").reasons.map((x) => x.code);
    expect(codes).not.toContain("header_shaped_token");
  });

  it("a surface with no percent-escape at all cannot match any arm", () => {
    for (const url of [
      "https://example.com/HTTP/1.1",
      "https://example.com/?x=Host:evil.com",
      "https://example.com/",
    ]) {
      expect(inspect(url).reasons.map((x) => x.code), url).not.toContain("header_shaped_token");
    }
  });
});
