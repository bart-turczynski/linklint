import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

/**
 * LINK-igoxaojd — scheme-less input whose host is a single label.
 *
 * First commit: pins the shipped behaviour. `POST` and a User-Agent string are
 * promoted to a host and come back `ok` at 0.00 with no reasons, which reads as
 * "inspected, nothing found" for text that was never a URL.
 */

/** Scheme-less inputs whose host is a single label (no dot). */
const SCHEMELESS_SINGLE_LABEL = [
  ["an HTTP method", "POST", "POST"],
  [
    "a User-Agent string",
    "Mozilla/5.0 (compatible; mybot/1.0; +http://example.com/bot)",
    "Mozilla",
  ],
] as const;

describe("scheme-less single-label input (LINK-igoxaojd)", () => {
  it.each(SCHEMELESS_SINGLE_LABEL)("%s is promoted to a host and scored 0", (_l, input, host) => {
    const result = inspect(input);
    expect(result.status).toBe("ok");
    expect(result.score).toBe(0);
    expect(result.parsed?.effectiveHost).toBe(host);
    expect(result.reasons).toEqual([]);
  });
});

describe("inputs the single-label rule must not move (LINK-igoxaojd)", () => {
  it.each([
    ["http://localhost/", "localhost"],
    ["http://intranet/", "intranet"],
    ["https://svc/", "svc"],
  ])("an explicit scheme keeps single-label host %s accepted", (input, host) => {
    const result = inspect(input);
    expect(result.status).toBe("ok");
    expect(result.parsed?.effectiveHost).toBe(host);
  });

  it.each([
    ["example.com", "example.com"],
    ["a.b", "a.b"],
  ])("a dotted bare host %s stays accepted", (input, host) => {
    const result = inspect(input);
    expect(result.status).toBe("ok");
    expect(result.parsed?.effectiveHost).toBe(host);
  });
});
