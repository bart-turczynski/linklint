import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * R1 — proves `InspectOptions.maxDecodeDepth` is actually wired through to the
 * bounded decoder used by the structural scans.
 *
 * `%250D%250A` is a double-encoded CRLF: it takes TWO percent-decode passes to
 * surface the raw CR/LF control bytes (`%250D` → `%0D` → CR). So decoding it
 * with a depth of 1 stops at `%0D%0A` (no control byte yet) and the
 * `control_char` detector stays silent; decoding with the default depth (4)
 * surfaces the CRLF and the detector fires. A behavior difference keyed solely
 * on `maxDecodeDepth` proves the option reaches the decode call site.
 */
const DOUBLE_ENCODED_CRLF = "http://example.com/%250D%250Aevil";

describe("maxDecodeDepth is wired through to the decoder", () => {
  it("depth 1 does not surface the double-encoded CRLF", () => {
    const codes = inspect(DOUBLE_ENCODED_CRLF, { maxDecodeDepth: 1 }).reasons.map((r) => r.code);
    expect(codes).not.toContain("control_char");
  });

  it("default depth surfaces the double-encoded CRLF", () => {
    const codes = inspect(DOUBLE_ENCODED_CRLF).reasons.map((r) => r.code);
    expect(codes).toContain("control_char");
  });

  it("explicit deep depth surfaces the double-encoded CRLF", () => {
    const codes = inspect(DOUBLE_ENCODED_CRLF, { maxDecodeDepth: 8 }).reasons.map((r) => r.code);
    expect(codes).toContain("control_char");
  });

  it("nonsense depth values fall back to the default (total, never throws)", () => {
    for (const bad of [-1, 2.5, Number.NaN, Number.POSITIVE_INFINITY] as number[]) {
      const codes = inspect(DOUBLE_ENCODED_CRLF, { maxDecodeDepth: bad }).reasons.map(
        (r) => r.code,
      );
      expect(codes).toContain("control_char");
    }
  });
});
