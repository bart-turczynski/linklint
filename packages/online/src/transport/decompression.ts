import {
  brotliDecompressSync,
  gunzipSync,
  inflateSync,
} from "node:zlib";

export class DecompressedLimitError extends Error {
  constructor() {
    super("decompressed response budget exceeded");
    this.name = "DecompressedLimitError";
  }
}

export class UnsupportedContentEncodingError extends Error {
  readonly encoding: string;

  constructor(encoding: string) {
    super("unsupported content encoding");
    this.name = "UnsupportedContentEncodingError";
    this.encoding = encoding;
  }
}

export class ContentDecompressionError extends Error {
  constructor() {
    super("response decompression failed");
    this.name = "ContentDecompressionError";
  }
}

export function decodeResponseBody(
  encoded: Uint8Array,
  headers: Readonly<Record<string, readonly string[]>>,
  maxOutputBytes: number,
): Uint8Array {
  // LINK-syeupoav: a zero-byte body is decoded, not decompressed. RFC 9110
  // 9.3.2 requires a HEAD response to carry the header fields it would send
  // for a GET — `Content-Encoding` included — with no body, and nginx, Apache
  // and Cloudflare all comply; a 204 and an empty 200 reach here the same way
  // on GET. Handing those zero bytes to zlib throws, which surfaced as a
  // `decompression-error` claiming the response was malformed when in fact
  // nothing was: the correct outcome is an empty body.
  //
  // This guard deliberately sits above the encoding parse, so an *unsupported*
  // declared encoding on an empty body is also answered with empty rather than
  // `UnsupportedContentEncodingError`. With zero bytes there is no
  // representation to decode and nothing can be smuggled, whereas every cause
  // in the transport vocabulary asserts something went wrong with a body that
  // exists. Auditing a peer's declared encoding is header inspection, and does
  // not belong in the decoder's error channel.
  if (encoded.byteLength === 0) return new Uint8Array(0);
  if (maxOutputBytes === 0) throw new DecompressedLimitError();
  const encodings = contentEncodings(headers);
  let body = encoded;
  for (const encoding of encodings.reverse()) {
    if (encoding === "identity") continue;
    try {
      const options = { maxOutputLength: maxOutputBytes };
      if (encoding === "gzip" || encoding === "x-gzip") {
        body = gunzipSync(body, options);
      } else if (encoding === "deflate") {
        body = inflateSync(body, options);
      } else if (encoding === "br") {
        body = brotliDecompressSync(body, options);
      } else {
        throw new UnsupportedContentEncodingError(encoding);
      }
    } catch (error) {
      if (error instanceof UnsupportedContentEncodingError) throw error;
      if (isOutputLimitError(error)) throw new DecompressedLimitError();
      throw new ContentDecompressionError();
    }
    if (body.byteLength > maxOutputBytes) throw new DecompressedLimitError();
  }
  if (body.byteLength > maxOutputBytes) throw new DecompressedLimitError();
  return new Uint8Array(body);
}

function contentEncodings(
  headers: Readonly<Record<string, readonly string[]>>,
): string[] {
  const values = Object.entries(headers)
    .filter(([name]) => name.toLowerCase() === "content-encoding")
    .flatMap(([, value]) => value);
  return values
    .flatMap((value) => value.split(","))
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value !== "");
}

function isOutputLimitError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ERR_BUFFER_TOO_LARGE"
  );
}
