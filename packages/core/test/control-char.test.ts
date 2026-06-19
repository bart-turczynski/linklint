import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanControlChar } from "../src/detectors/control-char.js";

const detail = (input: string): string => scanControlChar(input)[0]?.detail ?? "";
const codes = (input: string) => inspect(input).reasons.map((r) => r.code);

describe("J3 control_char — CRLF / protocol smuggling (Tsai BH US-17)", () => {
  it("percent-encoded CRLF %0D%0A is flagged (not caught by invisible_char)", () => {
    const r = inspect("http://127.0.0.1:6379/%0D%0ASLAVEOF");
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
    expect(detail(r.input)).toContain("crlf");
    expect(detail(r.input)).toContain("percent-encoded");
  });

  it("lone encoded LF %0A flags", () => {
    expect(codes("http://example.com/%0Arubbish")).toContain("control_char");
  });

  it("encoded TAB %09 as a host terminator", () => {
    const r = inspect("http://127.0.0.1%09foo.google.com");
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
    expect(detail(r.input)).toContain("tab");
  });

  it("double-encoded CRLF %250D%250A is flagged as double-encoded", () => {
    const r = inspect("http://example.com/%250D%250Aevil");
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
    expect(detail(r.input)).toContain("double-encoded");
  });

  it("double-encoded TAB %2509 -> %09 -> tab", () => {
    expect(detail("http://127.0.0.1%2509foo")).toContain("double-encoded");
    expect(detail("http://127.0.0.1%2509foo")).toContain("tab");
  });

  it("encoded NUL %00 truncation", () => {
    expect(detail("http://example.com/%00.evil.com")).toContain("null");
  });

  it("raw CR/LF in the path co-fires with invisible_char and names crlf [raw]", () => {
    const r = inspect("http://example.com/\r\nHELO");
    const found = r.reasons.map((x) => x.code);
    expect(found).toContain("control_char");
    expect(found).toContain("invisible_char");
    expect(detail(r.input)).toContain("raw");
  });

  it("bare whitespace inside a host-shaped authority (127.0.0.1 foo)", () => {
    const r = inspect("http://127.0.0.1 foo.google.com/");
    expect(r.reasons.map((x) => x.code)).toContain("control_char");
    expect(detail(r.input)).toContain("whitespace_in_host");
  });
});

describe("J3 control_char — scores on its own (SC-1) and emits one reason", () => {
  it("encoded CRLF reaches >= high (weight 0.6)", () => {
    const r = inspect("http://127.0.0.1:6379/%0D%0ASLAVEOF%20evil%200");
    expect(["high", "critical"]).toContain(r.severity);
    expect(r.score).toBeGreaterThan(0.5);
  });

  it("multiple control signals collapse to a single control_char reason", () => {
    const r = inspect("http://example.com/%0D%0A%09");
    const hits = r.reasons.filter((x) => x.code === "control_char");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.detail).toContain("crlf");
    expect(hits[0]!.detail).toContain("tab");
  });
});

describe("J3 control_char — must not over-flag legitimate input (SC-2)", () => {
  const benign = [
    "https://www.example.com/path?q=1#x",
    "https://example.com/a%20b/c", // encoded SPACE (0x20) is not a control char
    "https://example.com/?redirect=https%3A%2F%2Fok.com", // encoded structural, not control
    "https://example.com/search?q=hello%20world",
    "https://user:pass@example.com/login",
    "192.168.1.1",
    "https://例え.テスト/記事", // non-ASCII path, no control chars
    "https://example.com/a+b", // literal plus
  ];
  for (const input of benign) {
    it(`no control_char for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("control_char");
    });
  }

  it("a raw space in a PATH (not the authority) does not flag whitespace_in_host", () => {
    expect(detail("https://example.com/path with space")).not.toContain("whitespace_in_host");
  });

  it("non-URL prose with a space but no dot does not flag", () => {
    expect(scanControlChar("hello world")).toEqual([]);
  });
});

describe("J3 scanControlChar — total and decode-bomb safe", () => {
  it("returns [] for empty / clean input", () => {
    for (const i of ["", "   ", "https://example.com", "example.com"]) {
      expect(scanControlChar(i.trim())).toEqual([]);
    }
  });

  it("does not throw on adversarial nested percent chains", () => {
    expect(() => scanControlChar("http://x/" + "%25".repeat(50) + "0D")).not.toThrow();
  });
});
