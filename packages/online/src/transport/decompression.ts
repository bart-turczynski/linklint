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
  if (maxOutputBytes === 0 && encoded.byteLength > 0) throw new DecompressedLimitError();
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
