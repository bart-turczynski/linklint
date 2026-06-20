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

  it("returns empty for all-blank/comment input", () => {
    expect(parseUrlLines("\n\n# only comments\n   \n")).toEqual([]);
  });
});
