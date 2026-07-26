import { describe, expect, it } from "vitest";
import { inspect, WEIGHTS } from "../src/index.js";

/**
 * T2.3 (LINK-ibwuayzo) — low-byte-truncation code points.
 *
 * A code point above U+007F whose low byte is a dangerous ASCII byte, isolated
 * between two ASCII alphanumerics. A lossy UTF-16-to-byte narrowing materializes
 * the byte, so no byte-scan of the input can see it — this is the class
 * `control_char` cannot reach even though it handles every direct form.
 *
 * The ASCII-sandwich guard is the load-bearing part of the design and is
 * asserted in both directions below. Without it, the firing condition would be
 * "truncation-reachable", which covers 492 everyday CJK characters and would
 * flag a large share of real Chinese and Japanese URLs.
 */

const reasons = (url: string) => inspect(url, { agentMode: true }).reasons.map((r) => r.code);

describe("low_byte_truncation — fires on a dangerous low byte inside an ASCII sandwich", () => {
  it.each([
    ["https://example.com/a嘊b", "U+560A narrows to LF"],
    ["https://example.com/a嘍b", "U+560D narrows to CR"],
    ["https://example.com/aĊb", "U+010A narrows to LF — the family is unbounded"],
    ["https://example.com/x有y", "U+6709 (有) narrows to TAB"],
    ["https://example.com/1下2", "U+4E0B (下) narrows to VT, digits count as alphanumeric"],
    ["https://example.com/a一b", "U+4E00 (一) narrows to NUL"],
    ["https://example.com/a圯b", "U+572F narrows to '/' — re-parses the authority"],
    ["https://example.com/?q=a局b", "query component is scanned"],
    ["https://example.com/#a局b", "fragment component is scanned"],
  ])("%s (%s)", (url) => {
    expect(reasons(url)).toContain("low_byte_truncation");
  });

  it("scores 0.6 — parity with control_char, which catches the direct form", () => {
    // The truncation variant is strictly harder to see than a raw or
    // percent-encoded newline, so parity is the defensible floor: pricing it
    // higher would assert it is worse than an actual embedded newline.
    // Revisit is tracked at LINK-tyjxigyc.
    expect(WEIGHTS.low_byte_truncation).toBe(0.6);
    expect(WEIGHTS.low_byte_truncation).toBe(WEIGHTS.control_char);
  });

  it("catches the zero-width joiner in g<U+200D>oogle.com, whose low byte is 0x0D", () => {
    // Found independently by this check: the only one of 220 corpus URLs it
    // fires on, and it was already a known attack for a different reason.
    expect(reasons("https://g‍oogle.com/")).toContain("low_byte_truncation");
  });
});

describe("low_byte_truncation — the ASCII sandwich is required, not incidental", () => {
  it.each([
    ["https://example.jp/data下載.zip", "下載: 下 is reachable, but its neighbour is CJK"],
    ["https://example.cn/下載/index.html", "pure-CJK path segment, no ASCII either side"],
    ["https://example.cn/file名.pdf", "名 is preceded by ASCII but followed by '.'"],
    ["https://example.cn/上传/img001.jpg", "上传: neighbours are '/' and CJK"],
    ["https://example.kr/한국어/x.pdf", "Hangul run"],
    ["https://пример.рф/путь/файл.pdf", "Cyrillic run"],
  ])("%s (%s)", (url) => {
    expect(reasons(url)).not.toContain("low_byte_truncation");
  });

  it("stays quiet on non-ASCII whose low byte is harmless", () => {
    // U+4E2D (中) low byte 0x2D is '-', U+6587 (文) low byte 0x87 is not ASCII.
    expect(reasons("https://example.com/a中b")).not.toContain("low_byte_truncation");
    expect(reasons("https://example.com/a文b")).not.toContain("low_byte_truncation");
  });

  it("does not fire on a plain ASCII URL or on a real embedded control character", () => {
    expect(reasons("https://example.com/a/b")).not.toContain("low_byte_truncation");
    // A raw LF is control_char / invisible_char territory: the byte is really
    // there, so this check has nothing to add.
    expect(reasons("https://example.com/a\nb")).not.toContain("low_byte_truncation");
    expect(reasons("https://example.com/a%0Ab")).not.toContain("low_byte_truncation");
  });
});
