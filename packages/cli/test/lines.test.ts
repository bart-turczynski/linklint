import { describe, expect, it } from "vitest";
import { parseUrlLines } from "@linklint/cli";

describe("parseUrlLines", () => {
  it("skips blank lines and comment lines, trims, and keeps order", () => {
    const text = [
      "# a comment",
      "  https://first.example  ",
      "",
      "   ",
      "https://second.example",
      "   # indented comment",
      "\thttps://third.example\t",
    ].join("\n");
    expect(parseUrlLines(text)).toEqual([
      "https://first.example",
      "https://second.example",
      "https://third.example",
    ]);
  });

  // LINK-bitralnj. String.prototype.trim removes ECMA-262 LineTerminators, which
  // include U+2028/U+2029 — the two characters invisible_char scores as a
  // BLOCKER. Trimming them here sanitized the input before inspection, so the
  // same URL scored 1.00/critical as an argument and 0.00/info from a file.
  // The CLI must never clean an input into looking safer than it is.
  describe("does not trim away characters that carry a finding", () => {
    it("preserves a trailing U+2028", () => {
      expect(parseUrlLines("https://example.com/?a=\u2028\n")).toEqual([
        "https://example.com/?a=\u2028",
      ]);
    });

    it("preserves a trailing U+2029", () => {
      expect(parseUrlLines("https://example.com/#\u2029\n")).toEqual([
        "https://example.com/#\u2029",
      ]);
    });

    it("preserves a leading separator", () => {
      expect(parseUrlLines("\u2028https://example.com/\n")).toEqual([
        "\u2028https://example.com/",
      ]);
    });

    it("still trims ordinary surrounding whitespace", () => {
      expect(parseUrlLines("  \thttps://example.com/ \r\n")).toEqual(["https://example.com/"]);
    });

    it("still trims whitespace around a preserved separator", () => {
      expect(parseUrlLines("  https://example.com/?a=\u2028  \n")).toEqual([
        "https://example.com/?a=\u2028",
      ]);
    });
  });

  it("returns empty for all-blank/comment input", () => {
    expect(parseUrlLines("\n\n# only comments\n   \n")).toEqual([]);
  });
});
