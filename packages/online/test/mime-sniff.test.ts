import { describe, expect, it } from "vitest";

import {
  MIME_SNIFF_PREFIX_BYTES,
  sniffMimeType,
  type SniffMimeRule,
} from "../src/resolution/index.js";

/** Build a Uint8Array from an ASCII string. */
const ascii = (text: string): Uint8Array =>
  Uint8Array.from(text, (character) => character.charCodeAt(0));

/** Concatenate byte-ish inputs into one Uint8Array. */
const concat = (...parts: (Uint8Array | number[])[]): Uint8Array => {
  const flat: number[] = [];
  for (const part of parts) flat.push(...Array.from(part));
  return Uint8Array.from(flat);
};

describe("sniffMimeType byte signatures", () => {
  const signatureCases: ReadonlyArray<readonly [string, Uint8Array, string]> = [
    ["png", concat([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "image/png"],
    ["jpeg", concat([0xff, 0xd8, 0xff, 0xe0, 0x00]), "image/jpeg"],
    ["gif87a", ascii("GIF87a...."), "image/gif"],
    ["gif89a", ascii("GIF89a...."), "image/gif"],
    [
      "webp",
      concat(ascii("RIFF"), [0x2a, 0x00, 0x00, 0x00], ascii("WEBP")),
      "image/webp",
    ],
    ["bmp", ascii("BM....."), "image/bmp"],
    ["ico", concat([0x00, 0x00, 0x01, 0x00, 0x01]), "image/vnd.microsoft.icon"],
    ["cursor", concat([0x00, 0x00, 0x02, 0x00, 0x01]), "image/vnd.microsoft.icon"],
    ["pdf", ascii("%PDF-1.7"), "application/pdf"],
    ["postscript", ascii("%!PS-Adobe-3.0"), "application/postscript"],
    ["zip", concat([0x50, 0x4b, 0x03, 0x04]), "application/zip"],
    ["gzip", concat([0x1f, 0x8b, 0x08, 0x00]), "application/gzip"],
    [
      "rar",
      concat([0x52, 0x61, 0x72, 0x20, 0x1a, 0x07, 0x00]),
      "application/x-rar-compressed",
    ],
    ["xml", ascii("<?xml version=\"1.0\"?>"), "text/xml"],
  ];

  for (const [name, prefix, expected] of signatureCases) {
    it(`matches ${name} to ${expected} via the signature rule`, () => {
      const result = sniffMimeType(prefix);
      expect(result.computedEssence).toBe(expected);
      expect(result.rule).toBe<SniffMimeRule>("signature");
    });
  }

  it("respects the webp RIFF mask (only bytes 0-3 and 8-11 are fixed)", () => {
    const other = concat(ascii("RIFF"), [0x01, 0x02, 0x03, 0x04], ascii("WAVE"));
    expect(sniffMimeType(other).computedEssence).not.toBe("image/webp");
  });
});

describe("sniffMimeType HTML tag signatures", () => {
  const htmlCases: ReadonlyArray<readonly [string, string]> = [
    ["<!DOCTYPE HTML case", "<!doctype html>"],
    ["<HTML with space", "<html lang=en>"],
    ["<SCRIPT", "<script>alert(1)</script>"],
    ["<TITLE", "<title>x</title>"],
    ["<BODY", "<body>hi</body>"],
    ["<A terminated by space", "<a href=x>"],
  ];

  for (const [name, text] of htmlCases) {
    it(`sniffs ${name} as text/html`, () => {
      const result = sniffMimeType(ascii(text));
      expect(result.computedEssence).toBe("text/html");
      expect(result.rule).toBe<SniffMimeRule>("signature");
    });
  }

  it("matches the <!-- comment marker terminated by >", () => {
    expect(sniffMimeType(ascii("<!-->")).computedEssence).toBe("text/html");
  });

  it("matches case-insensitively and after leading ASCII whitespace", () => {
    expect(sniffMimeType(ascii("\n\t  <HtMl>")).computedEssence).toBe("text/html");
  });

  it("does NOT match an HTML tag token that is not tag-terminated", () => {
    const result = sniffMimeType(ascii("<HTMLZ and more plain text"));
    expect(result.computedEssence).toBe("text/plain");
    expect(result.rule).toBe<SniffMimeRule>("text-plain");
  });

  it("does NOT let <B shadow a longer <BODY token", () => {
    // "<BODY>" must not spuriously match "<B" (next byte O is not a terminator).
    expect(sniffMimeType(ascii("<BODY>")).computedEssence).toBe("text/html");
  });
});

describe("sniffMimeType text-or-binary rule", () => {
  const boms: ReadonlyArray<readonly [string, number[]]> = [
    ["UTF-16BE", [0xfe, 0xff, 0x00, 0x41]],
    ["UTF-16LE", [0xff, 0xfe, 0x41, 0x00]],
    ["UTF-8", [0xef, 0xbb, 0xbf, 0x41]],
  ];

  for (const [name, prefix] of boms) {
    it(`treats a ${name} BOM as text/plain even with binary-looking bytes`, () => {
      const result = sniffMimeType(Uint8Array.from(prefix));
      expect(result.computedEssence).toBe("text/plain");
      expect(result.rule).toBe<SniffMimeRule>("text-plain");
    });
  }

  it("classifies plain UTF-8 text as text/plain", () => {
    const result = sniffMimeType(ascii("just a normal sentence, nothing special."));
    expect(result.computedEssence).toBe("text/plain");
    expect(result.rule).toBe<SniffMimeRule>("text-plain");
  });

  it("classifies a body with a NUL byte and no signature as octet-stream", () => {
    const result = sniffMimeType(concat(ascii("hello"), [0x00], ascii("world")));
    expect(result.computedEssence).toBe("application/octet-stream");
    expect(result.rule).toBe<SniffMimeRule>("octet-stream");
  });

  it("treats an empty prefix as text/plain (no binary byte present)", () => {
    const result = sniffMimeType(new Uint8Array(0));
    expect(result.computedEssence).toBe("text/plain");
    expect(result.rule).toBe<SniffMimeRule>("text-plain");
  });

  it("only inspects the bounded resource-header prefix", () => {
    // A signature-free text run of exactly the bound, then a binary byte beyond it.
    const padded = concat(
      ascii("x".repeat(MIME_SNIFF_PREFIX_BYTES)),
      [0x00],
    );
    expect(sniffMimeType(padded).computedEssence).toBe("text/plain");
  });
});

describe("sniffMimeType declared essence parsing", () => {
  it("lowercases and strips parameters from a valid declared type", () => {
    expect(sniffMimeType(new Uint8Array(0), "text/HTML; charset=utf-8").declaredEssence)
      .toBe("text/html");
  });

  it("returns null for absent, empty, or garbage declared types", () => {
    expect(sniffMimeType(new Uint8Array(0)).declaredEssence).toBeNull();
    expect(sniffMimeType(new Uint8Array(0), null).declaredEssence).toBeNull();
    expect(sniffMimeType(new Uint8Array(0), "").declaredEssence).toBeNull();
    expect(sniffMimeType(new Uint8Array(0), "notamime").declaredEssence).toBeNull();
    expect(sniffMimeType(new Uint8Array(0), "text / html").declaredEssence).toBeNull();
    expect(sniffMimeType(new Uint8Array(0), "a/b/c").declaredEssence).toBeNull();
  });
});

describe("sniffMimeType deception signal", () => {
  it("keeps declared and computed essences independent for a mislabeled body", () => {
    const htmlBody = ascii("<script>document.location='https://evil.test'</script>");
    const result = sniffMimeType(htmlBody, "image/png");
    expect(result.declaredEssence).toBe("image/png");
    expect(result.computedEssence).toBe("text/html");
    expect(result.rule).toBe<SniffMimeRule>("signature");
  });
});
