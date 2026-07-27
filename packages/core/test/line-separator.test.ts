import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { isInvisibleNonBidi, isLineSeparator, stripInvisible } from "../src/unicode/format-chars.js";

const LS = " "; // LINE SEPARATOR
const PS = " "; // PARAGRAPH SEPARATOR

const codes = (url: string) => inspect(url).reasons.map((r) => r.code);

describe("V9 line/paragraph separators in invisible_char (LINK-bitralnj)", () => {
  // The root cause: U+2028/U+2029 are Unicode category Zl/Zp, NOT Cc/Cf, so the
  // \p{Cc}\p{Cf} class that catches U+200B and the Tags block never matched them.
  it("they are not Cc/Cf, which is why they were missed", () => {
    expect(/[\p{Cc}\p{Cf}]/u.test(LS)).toBe(false);
    expect(/[\p{Cc}\p{Cf}]/u.test(PS)).toBe(false);
    expect(isLineSeparator(LS)).toBe(true);
    expect(isLineSeparator(PS)).toBe(true);
    expect(isInvisibleNonBidi(LS)).toBe(true);
    expect(isInvisibleNonBidi(PS)).toBe(true);
  });

  for (const [name, sep] of [
    ["U+2028", LS],
    ["U+2029", PS],
  ] as const) {
    describe(name, () => {
      it("fires in the path", () => {
        expect(codes(`https://example.com/a${sep}b`)).toContain("invisible_char");
      });
      it("fires in the query", () => {
        expect(codes(`https://example.com/?a=${sep}`)).toContain("invisible_char");
      });
      it("fires in the fragment", () => {
        expect(codes(`https://example.com/#${sep}`)).toContain("invisible_char");
      });
      it("names the codepoint in the detail", () => {
        const reason = inspect(`https://example.com/a${sep}b`).reasons.find(
          (r) => r.code === "invisible_char",
        )!;
        expect(reason.detail).toContain(name);
      });
      it("is a blocker, like every other invisible character", () => {
        const result = inspect(`https://example.com/a${sep}b`);
        expect(result.score).toBe(1);
        expect(result.severity).toBe("critical");
      });
    });
  }

  // The detector's notion of "invisible" is deliberately wider than the parser's.
  // If these ever converge, a U+2028 in the host would be STRIPPED into a host
  // that parses cleanly, replacing a fail-closed `invalid` with a pass.
  describe("the parser's notion of invisible stays narrower on purpose", () => {
    it("stripInvisible does not remove line separators", () => {
      expect(stripInvisible(`a${LS}b`)).toBe(`a${LS}b`);
      expect(stripInvisible(`a${PS}b`)).toBe(`a${PS}b`);
    });

    it("a line separator in the HOST still fails closed", () => {
      for (const sep of [LS, PS]) {
        const result = inspect(`https://exam${sep}ple.com/`);
        expect(result.status).toBe("invalid");
        expect(result.score).toBeNull();
      }
    });
  });

  it("does not fire on a clean URL", () => {
    expect(codes("https://example.com/a/b?c=d#e")).not.toContain("invisible_char");
  });
});
