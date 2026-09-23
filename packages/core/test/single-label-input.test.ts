import { describe, expect, it } from "vitest";
import { inspect, parse } from "../src/index.js";

/**
 * LINK-igoxaojd — scheme-less input whose host is a single label.
 *
 * The first commit pinned the shipped behaviour: `POST` and a User-Agent
 * string were promoted to a host and came back `ok` at 0.00 with no reasons,
 * which reads as "inspected, nothing found" for text that was never a URL.
 * The decision on LINK-jzafufqv (option A) makes that input `invalid`, and
 * §1.1's fourth rule makes the invalid result name what failed. Architecture
 * §6.1.14 records the scope.
 */

/** Scheme-less inputs whose host is a single label (no dot). */
const SCHEMELESS_SINGLE_LABEL = [
  ["an HTTP method", "POST", "POST"],
  [
    "a User-Agent string",
    "Mozilla/5.0 (compatible; mybot/1.0; +http://example.com/bot)",
    "Mozilla",
  ],
  ["bare localhost", "localhost", "localhost"],
  ["a bare single label with a port", "localhost:8080", "localhost"],
  ["a bare single label behind userinfo", "user@intranet", "intranet"],
] as const;

const GENERIC = "input is not a parseable URL or hostname";

describe("scheme-less single-label input is invalid and says why (LINK-igoxaojd)", () => {
  it.each(SCHEMELESS_SINGLE_LABEL)("%s fails closed", (_l, input) => {
    const result = inspect(input);
    expect(result.status).toBe("invalid");
    expect(result.score).toBeNull();
    expect(result.severity).toBeNull();
    expect(result.parsed).toBeNull();
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
    expect(result.reasons.map((r) => r.weight)).toEqual([0]);
    expect(result.checksRun).toEqual([]);
    expect(result.checksSkipped).toEqual(["lexical", "resolution", "reputation"]);
    expect(parse(input)).toBeNull();
  });

  it.each(SCHEMELESS_SINGLE_LABEL)("%s: the parse_error names the host and the rule", (_l, input, host) => {
    const detail = inspect(input).reasons[0]!.detail;
    expect(detail).not.toBe(GENERIC);
    expect(detail).toContain(`the host '${host}' is a single label`);
    expect(detail).toContain("no scheme");
    expect(detail).toContain("'http://'");
    expect(detail).toContain("not inspected");
  });

  it("a single label split by a zero-width space is invalid too, explained by the structural scan", () => {
    // The dot test runs on the host with invisibles stripped, so `PO\u200bST`
    // is still one label. A structural finding already explains the input, so
    // no parse_error is emitted — the findings-bearing invalid shape.
    const result = inspect("PO\u200bST");
    expect(result.status).toBe("invalid");
    expect(result.score).toBeNull();
    expect(result.reasons.map((r) => r.code)).not.toContain("parse_error");
  });

  it("a scheme-less failure on other grounds keeps the generic fallback", () => {
    // Only a failure caused by the single-label rule alone is named; `hello
    // world` has whitespace in the host and never reached the rule.
    for (const input of ["hello world", "/etc/passwd", "ht!tp://%%%not a url"]) {
      const result = inspect(input);
      expect(result.status, input).toBe("invalid");
      expect(result.reasons[0]!.detail, input).toBe(GENERIC);
    }
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
    ["127.0.0.1", "127.0.0.1"],
    ["localhost.", "localhost."],
  ])("a bare host with a dot, %s, stays accepted", (input, host) => {
    const result = inspect(input);
    expect(result.status).toBe("ok");
    expect(result.parsed?.effectiveHost).toBe(host);
  });

  it.each([
    ["[::1]", "::1"],
    ["2130706433", "2130706433"],
    ["0x7f000001", "0x7f000001"],
  ])("a dotless bare IP literal, %s, stays accepted", (input, host) => {
    const result = inspect(input);
    expect(result.status).toBe("ok");
    expect(result.parsed?.effectiveHost).toBe(host);
    expect(result.parsed?.isIp).toBe(true);
  });

  it("a dotless obfuscated IPv4 keeps its scored finding", () => {
    // Exempting IP literals is what keeps `ip_obfuscation` reachable for the
    // integer and hex forms; rejecting them would trade a scored finding for an
    // unscored `invalid`.
    expect(inspect("2130706433").reasons.map((r) => r.code)).toContain("ip_obfuscation");
  });
});
