/**
 * Pure, zero-network implementation of the detection half of the WHATWG MIME
 * Sniffing standard (https://mimesniff.spec.whatwg.org/). Given a bounded
 * response prefix it computes an independent, byte-derived MIME essence and
 * parses the declared Content-Type essence. This primitive only *detects*; the
 * nosniff / consumer-context *interpretation* of the two essences lives in a
 * later unit and is intentionally out of scope here.
 */

/** Which rule produced a computed MIME essence. */
export type SniffMimeRule = "signature" | "text-plain" | "octet-stream";

export interface SniffedMimeType {
  /**
   * Declared Content-Type essence: `type/subtype`, lowercased, parameters
   * stripped; `null` if the header is absent or unparseable.
   */
  readonly declaredEssence: string | null;
  /**
   * Independent MIME essence computed from the byte prefix via the WHATWG
   * signature tables / text-or-binary rule. Always non-null.
   */
  readonly computedEssence: string;
  /** Which rule produced `computedEssence`. */
  readonly rule: SniffMimeRule;
}

/** Maximum resource-header prefix the sniffer inspects (WHATWG resource header size). */
export const MIME_SNIFF_PREFIX_BYTES = 1445;

/** WHATWG "whitespace byte" set used when skipping leading bytes. */
const WHITESPACE_BYTES = new Set([0x09, 0x0a, 0x0c, 0x0d, 0x20]);

/** Tag-terminating bytes: ASCII space and `>`. */
const TAG_TERMINATORS: readonly number[] = [0x20, 0x3e];

interface BinarySignature {
  readonly essence: string;
  /** `null` entries are "don't care" bytes (mask), matched at their offset. */
  readonly pattern: readonly (number | null)[];
}

/**
 * Leading-byte signatures in WHATWG match order. The first match wins.
 * `null` in a pattern is a masked byte (the RIFF filesize field for webp).
 */
const BINARY_SIGNATURES: readonly BinarySignature[] = [
  { essence: "image/gif", pattern: bytes("GIF87a") },
  { essence: "image/gif", pattern: bytes("GIF89a") },
  { essence: "image/png", pattern: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { essence: "image/jpeg", pattern: [0xff, 0xd8, 0xff] },
  {
    essence: "image/webp",
    pattern: [
      ...bytes("RIFF"),
      null,
      null,
      null,
      null,
      ...bytes("WEBP"),
    ],
  },
  { essence: "image/bmp", pattern: bytes("BM") },
  { essence: "image/vnd.microsoft.icon", pattern: [0x00, 0x00, 0x01, 0x00] },
  { essence: "image/vnd.microsoft.icon", pattern: [0x00, 0x00, 0x02, 0x00] },
  { essence: "application/pdf", pattern: bytes("%PDF-") },
  { essence: "application/postscript", pattern: bytes("%!PS-Adobe-") },
  { essence: "application/zip", pattern: [0x50, 0x4b, 0x03, 0x04] },
  { essence: "application/gzip", pattern: [0x1f, 0x8b, 0x08] },
  {
    essence: "application/x-rar-compressed",
    pattern: [0x52, 0x61, 0x72, 0x20, 0x1a, 0x07, 0x00],
  },
];

/**
 * HTML tag tokens matched case-insensitively after leading whitespace, each
 * followed by a tag-terminating byte. Order is irrelevant: every token is
 * matched in full plus its terminator, so no token can shadow another.
 */
const HTML_TAGS: readonly string[] = [
  "<!DOCTYPE HTML",
  "<HTML",
  "<HEAD",
  "<SCRIPT",
  "<IFRAME",
  "<H1",
  "<DIV",
  "<FONT",
  "<TABLE",
  "<A",
  "<STYLE",
  "<TITLE",
  "<B",
  "<BODY",
  "<BR",
  "<P",
];

/**
 * Compute the independent byte-derived MIME essence and parse the declared
 * essence. Pure and deterministic: never performs I/O and never throws.
 */
export function sniffMimeType(
  prefix: Uint8Array,
  declaredType?: string | null,
): SniffedMimeType {
  const view = prefix.subarray(0, MIME_SNIFF_PREFIX_BYTES);
  const computed = computeEssence(view);
  return {
    declaredEssence: parseDeclaredEssence(declaredType),
    computedEssence: computed.essence,
    rule: computed.rule,
  };
}

function computeEssence(
  view: Uint8Array,
): { readonly essence: string; readonly rule: SniffMimeRule } {
  for (const signature of BINARY_SIGNATURES) {
    if (matchesAt(view, 0, signature.pattern)) {
      return { essence: signature.essence, rule: "signature" };
    }
  }

  const whitespaceOffset = skipWhitespace(view);
  if (matchesAt(view, whitespaceOffset, bytes("<?xml"))) {
    return { essence: "text/xml", rule: "signature" };
  }
  if (matchesHtml(view, whitespaceOffset)) {
    return { essence: "text/html", rule: "signature" };
  }

  return textOrBinary(view);
}

function textOrBinary(
  view: Uint8Array,
): { readonly essence: string; readonly rule: SniffMimeRule } {
  if (hasBom(view)) {
    return { essence: "text/plain", rule: "text-plain" };
  }
  for (const byte of view) {
    if (isBinaryDataByte(byte)) {
      return { essence: "application/octet-stream", rule: "octet-stream" };
    }
  }
  return { essence: "text/plain", rule: "text-plain" };
}

function hasBom(view: Uint8Array): boolean {
  return (
    matchesAt(view, 0, [0xfe, 0xff]) ||
    matchesAt(view, 0, [0xff, 0xfe]) ||
    matchesAt(view, 0, [0xef, 0xbb, 0xbf])
  );
}

function isBinaryDataByte(byte: number): boolean {
  return (
    (byte >= 0x00 && byte <= 0x08) ||
    byte === 0x0b ||
    (byte >= 0x0e && byte <= 0x1a) ||
    (byte >= 0x1c && byte <= 0x1f)
  );
}

function matchesHtml(view: Uint8Array, offset: number): boolean {
  for (const tag of HTML_TAGS) {
    const end = matchTagTokenInsensitive(view, offset, tag);
    if (end >= 0 && end < view.length && isTagTerminator(view[end]!)) {
      return true;
    }
  }
  // The comment marker `<!--` is terminated by `>` only.
  const commentEnd = matchTagTokenInsensitive(view, offset, "<!--");
  return commentEnd >= 0 && commentEnd < view.length && view[commentEnd] === 0x3e;
}

function isTagTerminator(byte: number): boolean {
  return TAG_TERMINATORS.includes(byte);
}

/**
 * Match `token` at `offset` comparing ASCII letters case-insensitively and all
 * other bytes exactly. Returns the offset just past the token, or `-1` if the
 * token does not fit or does not match.
 */
function matchTagTokenInsensitive(
  view: Uint8Array,
  offset: number,
  token: string,
): number {
  if (offset + token.length > view.length) return -1;
  for (let index = 0; index < token.length; index += 1) {
    if (!byteMatchesInsensitive(view[offset + index]!, token.charCodeAt(index))) {
      return -1;
    }
  }
  return offset + token.length;
}

function byteMatchesInsensitive(actual: number, expected: number): boolean {
  return toLowerAscii(actual) === toLowerAscii(expected);
}

function toLowerAscii(byte: number): number {
  return byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte;
}

function skipWhitespace(view: Uint8Array): number {
  let offset = 0;
  while (offset < view.length && WHITESPACE_BYTES.has(view[offset]!)) {
    offset += 1;
  }
  return offset;
}

/** Exact/masked byte comparison of `pattern` at `offset`. */
function matchesAt(
  view: Uint8Array,
  offset: number,
  pattern: readonly (number | null)[],
): boolean {
  if (offset + pattern.length > view.length) return false;
  for (let index = 0; index < pattern.length; index += 1) {
    const expected = pattern[index];
    if (expected !== null && view[offset + index] !== expected) return false;
  }
  return true;
}

/** ASCII byte values of a literal token. */
function bytes(literal: string): number[] {
  const result: number[] = [];
  for (let index = 0; index < literal.length; index += 1) {
    result.push(literal.charCodeAt(index));
  }
  return result;
}

function parseDeclaredEssence(declaredType?: string | null): string | null {
  if (declaredType === undefined || declaredType === null) return null;
  const semicolon = declaredType.indexOf(";");
  const essence = (semicolon < 0 ? declaredType : declaredType.slice(0, semicolon))
    .trim()
    .toLowerCase();
  return /^[^/\s]+\/[^/\s]+$/.test(essence) ? essence : null;
}
