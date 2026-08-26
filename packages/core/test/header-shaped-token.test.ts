import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-dyqyhtgo (T2.4) — COMMIT 1 of 2. This file pins the gap OPEN.
//
// James Kettle's 2022 response-queue-poisoning work is the strongest possible
// case for a URL linter, because the disclosed payload is entirely a URL: the
// path and query carry an encoded SP followed by an HTTP-version token, or an
// encoded CRLF followed by a header field line, so a component that writes the
// request target onto the wire without re-encoding emits two requests where the
// caller wrote one.
//
// As of this commit linklint says nothing about any of the payload rows below:
// score 0.00, severity `info`, and an EMPTY reason list — which under §1.1's
// fourth rule asserts "there is nothing to say about this URL".
//
// `control_char` covers the neighbouring case and cannot reach these. Its own
// entry in docs/reason-codes.md states the exclusion outright: "an encoded
// **space** (`%20`) is not a control character and never flags". The encoded SP
// is exactly the byte the request-line grammar delimits on, so the one shape
// `control_char` deliberately skips is the one this ticket is about.
//
// The next commit registers `header_shaped_token` and turns the payload
// assertions red, then rewrites them. The control assertions below do NOT
// change in either commit: they are the false-positive profile, and they are
// what proves the rule gates on the COMBINATION rather than on the bare token.

/** The two URLs the gap matrix quotes verbatim, plus the rest of the family. */
const PAYLOADS: ReadonlyArray<readonly [string, string]> = [
  ["https://example.com/?x=Host:%20evil.com", "gap-matrix row: Host field line in a query value"],
  ["https://example.com/a%20HTTP/1.1", "gap-matrix row: request-line shape in the path"],
  ["https://example.com/?x=Transfer-Encoding:%20chunked", "the TE field line that desyncs"],
  ["https://example.com/?x=Content-Length:%200", "the CL field line that desyncs"],
  ["https://example.com/?x=Expect:%20100-continue", "Expect: 100-continue field line"],
];

/**
 * Benign rows that must stay quiet in BOTH commits. Each carries a
 * header-shaped token WITHOUT the encoded wire separator that would put it in
 * request-line or field-line position, or with a value outside the field's own
 * grammar — a docs search, a blog slug, an event listing.
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

describe("header-shaped tokens are NOT detected yet (LINK-dyqyhtgo, pre-fix)", () => {
  it.each(PAYLOADS)("%s (%s) scores 0.00 with an EMPTY reason list", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons).toEqual([]);
  });

  it("control_char cannot reach them — %20 is excluded from it by design", () => {
    for (const [url] of PAYLOADS) {
      const codes = inspect(url).reasons.map((x) => x.code);
      expect(codes).not.toContain("control_char");
    }
  });
});

describe("the encoded-CRLF neighbour is ALREADY covered — verified, then left alone", () => {
  // Re-derived rather than trusted. An encoded CRLF in the path or query is
  // `control_char` at 0.60 today, with `encoding_obfuscation` alongside it, so
  // the new code is additive on this row rather than the thing that finds it.
  it("an encoded CRLF payload already reaches 0.74/high", () => {
    const r = inspect("https://example.com/?x=Host:%20evil.com%0d%0a");
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
  });
});

describe("benign header-shaped text stays quiet (false-positive controls)", () => {
  it.each(CONTROLS)("%s (%s) raises no header-shaped-token finding", (url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).not.toContain("header_shaped_token");
  });
});
