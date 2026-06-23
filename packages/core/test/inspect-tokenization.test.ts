import { beforeEach, describe, expect, it, vi } from "vitest";

const tokenizerCalls = vi.hoisted(() => ({ count: 0 }));

vi.mock("../src/parse/raw-tokens.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/parse/raw-tokens.js")>();
  return {
    ...actual,
    tokenizeRawUrl: vi.fn((prepared: string) => {
      tokenizerCalls.count += 1;
      return actual.tokenizeRawUrl(prepared);
    }),
  };
});

const { inspect } = await import("../src/inspect.js");

describe("inspect — shared raw tokenization", () => {
  beforeEach(() => {
    tokenizerCalls.count = 0;
  });

  it("tokenizes a prepared input once for structural scans and parsing", () => {
    const result = inspect("https://paypal.com@evil.example.com/login");

    expect(result.status).toBe("ok");
    expect(tokenizerCalls.count).toBe(1);
  });

  it("still tokenizes invalid input once so structural scans can explain it", () => {
    const result = inspect("http://");

    expect(result.status).toBe("invalid");
    expect(tokenizerCalls.count).toBe(1);
  });
});
