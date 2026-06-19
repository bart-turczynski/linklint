import { describe, expect, it } from "vitest";
import { analyzeLabelScripts, scriptOf } from "../src/unicode/scripts.js";
import { findConfusables } from "../src/unicode/confusables.js";
import { boundedDecode, decodeOnce } from "../src/parse/decode.js";
import { hasNormalizationDelta, toAscii, toUnicode } from "../src/unicode/idna.js";

const CYR_A = String.fromCodePoint(0x0430); // а

describe("scriptOf", () => {
  it("classifies common scripts and treats digits/punct as neutral", () => {
    expect(scriptOf("a")).toBe("Latin");
    expect(scriptOf(CYR_A)).toBe("Cyrillic");
    expect(scriptOf("1")).toBeNull();
    expect(scriptOf("-")).toBeNull();
  });
});

describe("analyzeLabelScripts (mixing)", () => {
  it("single-script labels are not mixed", () => {
    expect(analyzeLabelScripts("paypal").mixed).toBe(false);
    expect(analyzeLabelScripts("пример").mixed).toBe(false); // пример
  });

  it("Latin+Cyrillic in one label is mixed", () => {
    expect(analyzeLabelScripts(`p${CYR_A}ypal`).mixed).toBe(true);
  });

  it("Japanese Han+Hiragana+Katakana is compatible (not flagged)", () => {
    // 日本ノ (Han + Katakana)
    expect(analyzeLabelScripts("日本ノ").mixed).toBe(false);
  });
});

describe("findConfusables", () => {
  it("finds the Cyrillic 'а' confusable with Latin a and records position", () => {
    const c = findConfusables(`p${CYR_A}ypal`, "host");
    expect(c).toHaveLength(1);
    expect(c[0]!.position).toBe(1);
    expect(c[0]!.component).toBe("host");
    expect(c[0]!.confusableWith).toContain("a");
  });

  it("returns nothing for pure ASCII", () => {
    expect(findConfusables("paypal", "host")).toHaveLength(0);
  });
});

describe("boundedDecode", () => {
  it("decodes a single layer", () => {
    expect(decodeOnce("a%2Fb")).toBe("a/b");
    expect(boundedDecode("a%2Fb").passes).toBe(1);
  });

  it("detects nested encoding and caps depth", () => {
    const r = boundedDecode("%252e", 4); // %25 -> %, then %2e -> .
    expect(r.passes).toBe(2);
    expect(r.decoded).toBe(".");
  });

  it("caps depth on deeply nested encoding (no decode-bomb)", () => {
    // "." encoded 5 times: each pass peels exactly one layer.
    const nested = `%${"25".repeat(5)}2e`;
    const r = boundedDecode(nested, 3);
    expect(r.passes).toBe(3);
    expect(r.truncated).toBe(true);
  });
});

describe("idna", () => {
  it("converts to/from ACE", () => {
    expect(toAscii("bücher.de")).toBe("xn--bcher-kva.de"); // bücher.de
    expect(toUnicode("xn--bcher-kva.de")).toBe("bücher.de");
  });

  it("flags an IDN as having a normalization delta, ASCII hosts not", () => {
    expect(hasNormalizationDelta("bücher.de")).toBe(true);
    expect(hasNormalizationDelta("xn--bcher-kva.de")).toBe(true);
    expect(hasNormalizationDelta("example.com")).toBe(false);
  });
});
