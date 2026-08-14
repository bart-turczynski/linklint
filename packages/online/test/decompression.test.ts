/**
 * Direct coverage for `decodeResponseBody` (LINK-syeupoav).
 *
 * The decoder previously had no unit tests at all — it was only ever reached
 * through `SafeTransport`, and every test that reached it supplied a NON-EMPTY
 * body. That is what let the empty-body defect survive: zero bytes carrying a
 * `Content-Encoding` went straight to zlib, which throws, and the transport
 * reported `decompression-error` for a response that was never malformed.
 */
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  ContentDecompressionError,
  DecompressedLimitError,
  decodeResponseBody,
  UnsupportedContentEncodingError,
} from "../src/transport/decompression.js";

const BUDGET = 1_000_000;

function headers(encoding?: string): Record<string, readonly string[]> {
  return encoding === undefined ? {} : { "content-encoding": [encoding] };
}

describe("decodeResponseBody empty bodies (LINK-syeupoav)", () => {
  /**
   * RFC 9110 9.3.2 requires a HEAD response to carry the header fields it
   * would send for a GET, `Content-Encoding` included, with no body. A 204 and
   * an empty 200 reach the same code path on GET.
   */
  it.each(["gzip", "x-gzip", "deflate", "br", "identity"])(
    "returns an empty body for a zero-byte %s response instead of throwing",
    (encoding) => {
      const decoded = decodeResponseBody(new Uint8Array(0), headers(encoding), BUDGET);
      expect(decoded.byteLength).toBe(0);
    },
  );

  it("returns an empty body for zero bytes under a stacked encoding", () => {
    const decoded = decodeResponseBody(new Uint8Array(0), { "content-encoding": ["gzip, br"] }, BUDGET);
    expect(decoded.byteLength).toBe(0);
  });

  /**
   * The guard sits ABOVE the encoding parse deliberately. With zero bytes there
   * is no representation to decode and nothing can be smuggled, whereas every
   * cause in the transport vocabulary asserts something went wrong with a body
   * that exists. Auditing a peer's declared encoding is header inspection and
   * does not belong in the decoder's error channel.
   */
  it("returns an empty body for zero bytes under an UNSUPPORTED encoding", () => {
    const decoded = decodeResponseBody(new Uint8Array(0), headers("compress"), BUDGET);
    expect(decoded.byteLength).toBe(0);
  });

  it("returns an empty body for zero bytes even under a zero decompressed budget", () => {
    expect(decodeResponseBody(new Uint8Array(0), headers("gzip"), 0).byteLength).toBe(0);
  });

  it("still refuses a NON-EMPTY body under a zero decompressed budget", () => {
    expect(() => decodeResponseBody(gzipSync("x"), headers("gzip"), 0))
      .toThrow(DecompressedLimitError);
  });
});

describe("decodeResponseBody non-empty bodies", () => {
  const CODECS = [
    { encoding: "gzip", compress: gzipSync },
    { encoding: "deflate", compress: deflateSync },
    { encoding: "br", compress: brotliCompressSync },
  ] as const;

  it.each(CODECS)("round-trips a $encoding body", ({ encoding, compress }) => {
    const raw = "payload".repeat(64);
    const decoded = decodeResponseBody(compress(raw), headers(encoding), BUDGET);
    expect(Buffer.from(decoded).toString("utf8")).toBe(raw);
  });

  it("passes an identity body through unchanged", () => {
    const raw = new Uint8Array([1, 2, 3]);
    expect([...decodeResponseBody(raw, headers("identity"), BUDGET)]).toEqual([1, 2, 3]);
  });

  /**
   * The empty-body guard must not become a general "malformed input is fine"
   * rule: garbage that is not a valid member of the declared encoding is still
   * a decompression failure.
   */
  it.each(CODECS)("still reports $encoding garbage as a decompression failure", ({ encoding }) => {
    expect(() => decodeResponseBody(new Uint8Array([0, 1, 2, 3]), headers(encoding), BUDGET))
      .toThrow(ContentDecompressionError);
  });

  it("still rejects an unsupported encoding on a non-empty body", () => {
    expect(() => decodeResponseBody(new Uint8Array([1]), headers("compress"), BUDGET))
      .toThrow(UnsupportedContentEncodingError);
  });

  it("refuses a body that decodes past the budget", () => {
    expect(() => decodeResponseBody(gzipSync("x".repeat(4_096)), headers("gzip"), 128))
      .toThrow(DecompressedLimitError);
  });
});
