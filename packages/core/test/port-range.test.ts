import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { parse } from "../src/parse/parse.js";

/**
 * LINK-drucugmm — decimal URL ports are bounded to WHATWG's range.
 *
 * Before this suite, `parseRawParts` validated only that the tail after `:` was
 * decimal SYNTAX and converted it with `Number()`. `http://example.com:999999/`
 * came back `status: "ok"` with `port: 999999`, and
 * `http://example.com:<400 nines>/` came back `ok` with `port: Infinity` —
 * which `JSON.stringify` renders as `null`, making it indistinguishable from
 * "no port" to every consumer of the JSON channel.
 *
 * linklint never connects from the offline core, so this was never an SSRF dial
 * bypass. It was a *diagnostic* defect: linklint reported a clean parse for a
 * string that WHATWG — and therefore browsers, `fetch`, and any downstream
 * consumer — refuses to parse at all.
 *
 * **The range is `0`–`65535` inclusive, matching WHATWG exactly**, including
 * WHATWG's acceptance of port `0`. The reasoning is pinned in the `MAX_PORT`
 * comment in `src/parse/raw-parts.ts`: `0` is syntactically legal and this is a
 * syntax parser, so rejecting it would manufacture the very consumer
 * disagreement this change removes. Out of range is never clamped or wrapped —
 * it makes the whole authority unparseable, which routes to `status: "invalid"`
 * with the existing `parse_error` reason. No new reason code is minted.
 */

/** WHATWG's verdict on a URL string: its numeric port, the scheme default, or refusal. */
type Whatwg = { ok: false } | { ok: true; port: number | null };

/**
 * `port === ""` in the WHATWG model means "the scheme's default, dropped from
 * the serialization" — not "no port". Reported here as `null` so the caller can
 * substitute the default rather than mistake it for a portless URL.
 */
function whatwg(url: string): Whatwg {
  try {
    const u = new URL(url);
    return { ok: true, port: u.port === "" ? null : Number(u.port) };
  } catch {
    return { ok: false };
  }
}

describe("decimal port bounds — the Done-list cases (LINK-drucugmm)", () => {
  /** Every outcome the ticket demanded be explicit, in one table. */
  const CASES: ReadonlyArray<
    readonly [label: string, url: string, expected: number | "invalid"]
  > = [
    // ── In range: parsed, verbatim, no clamping ──────────────────────────────
    ["zero is a legal written port", "http://example.com:0/", 0],
    ["one", "http://example.com:1/", 1],
    ["the scheme default", "http://example.com:80/", 80],
    ["a common non-standard port", "https://example.com:8443/", 8443],
    ["the ceiling, 65535", "http://example.com:65535/", 65535],
    ["leading zeros are stripped, not rejected", "http://example.com:0000080/", 80],
    ["leading zeros up to the ceiling", "http://example.com:00065535/", 65535],
    ["400 zeros is still port 0", `http://example.com:${"0".repeat(400)}/`, 0],

    // ── Out of range: invalid, never clamped or wrapped ──────────────────────
    ["one past the ceiling, 65536", "http://example.com:65536/", "invalid"],
    ["leading zeros do not smuggle 65536 in", "http://example.com:065536/", "invalid"],
    ["the ticket's case, 999999", "http://example.com:999999/", "invalid"],
    ["2^16", "http://example.com:65536/", "invalid"],
    ["2^32", "http://example.com:4294967296/", "invalid"],
    ["past Number.MAX_SAFE_INTEGER", "http://example.com:18446744073709551616/", "invalid"],
    ["400 nines — converts to Infinity", `http://example.com:${"9".repeat(400)}/`, "invalid"],
    ["10k digits", `http://example.com:${"7".repeat(10000)}/`, "invalid"],

    // ── Signed forms: not a port claim at all, so not a host either ──────────
    ["negative port", "http://example.com:-80/", "invalid"],
    ["explicitly signed port", "http://example.com:+80/", "invalid"],
    ["negative out-of-range port", "http://example.com:-999999/", "invalid"],

    // ── The bracketed IPv6 branch had the identical gap ──────────────────────
    ["IPv6 with port zero", "http://[::1]:0/", 0],
    ["IPv6 at the ceiling", "http://[::1]:65535/", 65535],
    ["IPv6 one past the ceiling", "http://[::1]:65536/", "invalid"],
    ["IPv6 far past the ceiling", "http://[::1]:99999/", "invalid"],
    ["IPv6 with 400 nines", `http://[::1]:${"9".repeat(400)}/`, "invalid"],
  ];

  it.each(CASES)("%s", (_label, url, expected) => {
    const ctx = parse(url);
    if (expected === "invalid") {
      expect(ctx).toBeNull();
    } else {
      expect(ctx).not.toBeNull();
      expect(ctx!.port).toBe(expected);
    }
  });

  it.each(CASES)("surfaces the same outcome through inspect(): %s", (_label, url, expected) => {
    const result = inspect(url);
    if (expected === "invalid") {
      expect(result.status).toBe("invalid");
      expect(result.parsed).toBeNull();
      expect(result.score).toBeNull();
      expect(result.severity).toBeNull();
      // Reuses the existing meta code — no port-specific reason code was minted.
      expect(result.reasons.map((r) => r.code)).toContain("parse_error");
    } else {
      expect(result.status).toBe("ok");
      expect(result.parsed!.port).toBe(expected);
    }
  });

  it("never emits a non-finite port", () => {
    // The pre-fix failure mode: `Number("9".repeat(400))` is `Infinity`, and
    // `JSON.stringify({ port: Infinity })` is `{"port":null}` — a consumer
    // reading the JSON channel could not tell it from a portless URL.
    for (const [, url] of CASES) {
      const port = inspect(url).parsed?.port ?? null;
      if (port !== null) expect(Number.isSafeInteger(port)).toBe(true);
    }
    const infinite = inspect(`http://example.com:${"9".repeat(400)}/`);
    expect(infinite.status).toBe("invalid");
    expect(JSON.parse(JSON.stringify(infinite)).parsed).toBeNull();
  });

  it("does not clamp or wrap an out-of-range port", () => {
    // A clamp would report 65535; a 16-bit wrap would report 65536 % 65536 = 0
    // and 999999 % 65536 = 16959. All three would attribute a port the input
    // never named, so the parse is refused instead.
    for (const url of ["http://example.com:65536/", "http://example.com:999999/"]) {
      expect(inspect(url).parsed).toBeNull();
    }
  });
});

describe("differential against WHATWG URL semantics (LINK-drucugmm)", () => {
  /**
   * Scope: digits-only port claims, which is exactly what this fix governs. The
   * empty-port form (`http://example.com:/`) is deliberately excluded — WHATWG
   * accepts it as the scheme default while linklint has always called it
   * unparseable, a pre-existing divergence outside this ticket.
   */
  const PORTS: readonly string[] = [
    "0",
    "1",
    "21",
    "80",
    "443",
    "8080",
    "8443",
    "65534",
    "65535",
    "65536",
    "65537",
    "70000",
    "99999",
    "100000",
    "999999",
    "4294967296",
    "18446744073709551616",
    "0000080",
    "00065535",
    "065536",
    "00000",
    "0".repeat(400),
    "9".repeat(400),
    "1".repeat(20),
  ];

  /** WHATWG drops a port equal to the scheme default; substitute it back. */
  const DEFAULTS: Record<string, number> = { http: 80, https: 443 };

  const HOSTS: readonly string[] = ["example.com", "[::1]"];
  const SCHEMES: readonly string[] = ["http", "https"];

  const MATRIX = SCHEMES.flatMap((scheme) =>
    HOSTS.flatMap((host) => PORTS.map((port) => [scheme, host, port] as const)),
  );

  it.each(MATRIX)("%s://%s:%s/ — agrees with new URL() on acceptance", (scheme, host, port) => {
    const url = `${scheme}://${host}:${port}/`;
    const reference = whatwg(url);
    const ctx = parse(url);

    expect(ctx !== null, `linklint and WHATWG disagree on whether ${url.slice(0, 60)} parses`).toBe(
      reference.ok,
    );

    if (reference.ok && ctx !== null) {
      const expected = reference.port ?? DEFAULTS[scheme]!;
      expect(ctx.port).toBe(expected);
    }
  });

  it("agrees that signed ports are not URLs", () => {
    for (const url of [
      "http://example.com:-80/",
      "http://example.com:+80/",
      "http://[::1]:-1/",
      "http://example.com:-0/",
    ]) {
      expect(whatwg(url).ok).toBe(false);
      expect(parse(url)).toBeNull();
    }
  });
});

describe("downstream consumers of ctx.port (LINK-drucugmm)", () => {
  function reasonCodes(url: string, opts: Parameters<typeof inspect>[1]): string[] {
    return inspect(url, opts).reasons.map((r) => r.code);
  }

  it("keeps the port policy axis reachable for in-range ports", () => {
    expect(reasonCodes("http://example.com:65535/", { denyNonStandardPorts: true })).toContain(
      "port_denied",
    );
    expect(reasonCodes("http://example.com:8080/", { denyPorts: [8080] })).toContain("port_denied");
  });

  it("no longer renders an impossible port in a port_denied detail", () => {
    // Before the bound, `denyNonStandardPorts` produced the detail
    // "port 999999 is non-standard for scheme 'http'" — a policy verdict about
    // a port no transport can carry. The input is now rejected upstream, so the
    // policy channel never sees it.
    const result = inspect("http://example.com:999999/", { denyNonStandardPorts: true });
    expect(result.status).toBe("invalid");
    expect(result.reasons.map((r) => r.code)).not.toContain("port_denied");
  });
});
