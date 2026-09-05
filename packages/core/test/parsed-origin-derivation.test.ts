import { describe, expect, it } from "vitest";

import { inspect } from "../src/index.js";
import type { ParsedUrl } from "../src/schema/types.js";

/**
 * LINK-vycgfumd — what `inspect().parsed` actually reports about origin, and
 * what a caller who derives a URL relationship from it alone therefore gets.
 *
 * This file exists BEFORE the comparator it licenses, and it is useful without
 * it. Two jobs:
 *
 *   1. PIN the four normalizations `parse()` does NOT apply. Each one is a case
 *      where two spellings of one origin land on two different `parsed` values.
 *      They are not defects — `ParsedUrl` reports *what was written*, and the
 *      character-level detectors need that. They are the reason a comparator
 *      cannot read `parsed` field-for-field and compare.
 *   2. MEASURE the packaging question that decided whether `compareUrls()`
 *      ships at all: is a same-origin / same-site answer derivable from the
 *      published `parsed` surface (`scheme`, `effectiveHost`, `port`,
 *      `registrableDomain`) by an informed caller? The `NAIVE` derivation below
 *      is the best such caller can do without an IDNA implementation and an IP
 *      canonicalizer of their own. Where it disagrees with the right answer,
 *      the disagreement is pinned as a WRONG row — that is the evidence, and if
 *      one of those rows ever starts agreeing, this test says so.
 */

const parsedOf = (input: string): ParsedUrl => {
  const result = inspect(input);
  if (result.parsed === null) throw new Error(`expected a parsed result for ${input}`);
  return result.parsed;
};

describe("parse() reports what was written — the four unapplied normalizations", () => {
  it("does not elide a default port: `:443` under https survives as 443", () => {
    expect(parsedOf("https://ex.com:443/").port).toBe(443);
    expect(parsedOf("https://ex.com/").port).toBeNull();
    expect(parsedOf("http://ex.com:80/").port).toBe(80);
    expect(parsedOf("http://ex.com/").port).toBeNull();
  });

  it("does not case-fold the host: `EX.com` survives as written", () => {
    expect(parsedOf("http://EX.com/").effectiveHost).toBe("EX.com");
    expect(parsedOf("http://ex.com/").effectiveHost).toBe("ex.com");
    // The PSL view IS folded, because tldts folds it — so the two halves of
    // `parsed` disagree about case, which is its own reason not to mix them.
    expect(parsedOf("http://EX.com/").registrableDomain).toBe("ex.com");
  });

  it("does not strip the trailing root dot: `ex.com.` survives as written", () => {
    expect(parsedOf("https://ex.com./").effectiveHost).toBe("ex.com.");
    expect(parsedOf("https://ex.com/").effectiveHost).toBe("ex.com");
    // Same disagreement inside one result: tldts drops the root label.
    expect(parsedOf("https://ex.com./").registrableDomain).toBe("ex.com");
  });

  it("does not reconcile A-label and U-label spellings of one host", () => {
    const uLabel = parsedOf("https://münchen.de/");
    const aLabel = parsedOf("https://xn--mnchen-3ya.de/");
    expect(uLabel.effectiveHost).toBe("münchen.de");
    expect(aLabel.effectiveHost).toBe("xn--mnchen-3ya.de");
    // And neither does the PSL view: `registrableDomain` differs too, so there
    // is no field on `parsed` on which these two spellings compare equal.
    expect(uLabel.registrableDomain).toBe("münchen.de");
    expect(aLabel.registrableDomain).toBe("xn--mnchen-3ya.de");
    expect(uLabel.registrableDomain).not.toBe(aLabel.registrableDomain);
  });
});

describe("parse() reports what was written — opaque and address-literal hosts", () => {
  it.each([
    ["data:text/html,hi", "data"],
    ["file:///etc/passwd", "file"],
    ["about:blank", "about"],
  ])("%s is hostless: every host-shaped field is null", (input, scheme) => {
    const parsed = parsedOf(input);
    expect(parsed.scheme).toBe(scheme);
    expect(parsed.effectiveHost).toBeNull();
    expect(parsed.registrableDomain).toBeNull();
    expect(parsed.publicSuffix).toBeNull();
    expect(parsed.port).toBeNull();
    // The load-bearing observation for the comparator: "hostless" and "could
    // not be parsed" are the SAME null here, on a result whose status is `ok`.
    expect(inspect(input).status).toBe("ok");
  });

  it("reports an IP literal as written, with no registrable domain", () => {
    expect(parsedOf("http://0x7f000001/").effectiveHost).toBe("0x7f000001");
    expect(parsedOf("http://127.0.0.1/").effectiveHost).toBe("127.0.0.1");
    expect(parsedOf("http://[::1]/").effectiveHost).toBe("::1");
    expect(parsedOf("http://[0:0:0:0:0:0:0:1]/").effectiveHost).toBe("0:0:0:0:0:0:0:1");
    for (const input of ["http://0x7f000001/", "http://[::1]/"]) {
      expect(parsedOf(input).isIp).toBe(true);
      expect(parsedOf(input).registrableDomain).toBeNull();
    }
  });
});

/**
 * The derivation an informed caller writes from the published `parsed` surface
 * alone: fold case, drop a trailing root dot, elide the scheme's default port,
 * compare. It is deliberately the STRONGEST such attempt — it already applies
 * three of the four normalizations pinned above — so that the rows it still
 * gets wrong are wrong for a structural reason and not for want of effort.
 */
const DEFAULT_PORT: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
};

const naiveHost = (parsed: ParsedUrl): string | null =>
  parsed.effectiveHost === null
    ? null
    : parsed.effectiveHost.toLowerCase().replace(/\.$/, "");

const naivePort = (parsed: ParsedUrl): number | null =>
  parsed.port ?? (parsed.scheme === null ? null : (DEFAULT_PORT[parsed.scheme] ?? null));

/** Same origin, as far as `parsed` alone can tell. */
const naiveSameOrigin = (left: string, right: string): boolean => {
  const a = parsedOf(left);
  const b = parsedOf(right);
  return (
    a.scheme === b.scheme && naiveHost(a) === naiveHost(b) && naivePort(a) === naivePort(b)
  );
};

/** Same site under the ICANN-only view, as far as `parsed` alone can tell. */
const naiveSameSiteIcann = (left: string, right: string): boolean =>
  parsedOf(left).registrableDomain === parsedOf(right).registrableDomain;

describe("deriving a relationship from `parsed` alone — where it holds", () => {
  it.each([
    ["default port elided", "https://ex.com:443/", "https://ex.com/"],
    ["host case folded", "http://EX.com/a", "http://ex.com/b"],
    ["trailing root dot dropped", "https://ex.com./", "https://ex.com/"],
    ["plain agreement", "https://ex.com/one", "https://ex.com/two"],
    ["port genuinely differs", "https://ex.com:8443/", "https://ex.com/"],
  ])("%s", (label, left, right) => {
    const expected = label !== "port genuinely differs";
    expect(naiveSameOrigin(left, right), label).toBe(expected);
  });
});

/**
 * The rows that decided the packaging question. Each is a pair whose right
 * answer is known independently of linklint — from the WHATWG URL Standard's
 * host parser (which runs UTS-46 ToASCII and canonicalizes IP literals) and
 * from its rule that an opaque origin is not equal to any origin, itself
 * included. In every row the derivation from `parsed` alone returns the other
 * one.
 */
describe("deriving a relationship from `parsed` alone — where it is WRONG", () => {
  it("calls one host under two spellings two different origins", () => {
    // WHATWG host parsing maps both spellings to `xn--mnchen-3ya.de`, so these
    // are the same origin. Nothing on `parsed` says so.
    expect(naiveSameOrigin("https://münchen.de/", "https://xn--mnchen-3ya.de/")).toBe(false);
    expect(naiveSameSiteIcann("https://münchen.de/", "https://xn--mnchen-3ya.de/")).toBe(
      false,
    );
  });

  it("calls two opaque origins the same origin", () => {
    // Each parse of an opaque-origin URL yields a fresh opaque origin, and two
    // opaque origins are not equal — not even two parses of the same string.
    expect(naiveSameOrigin("data:text/html,hi", "data:text/html,hi")).toBe(true);
    expect(naiveSameOrigin("file:///a", "file:///b")).toBe(true);
    expect(naiveSameOrigin("about:blank", "about:blank")).toBe(true);
    // …and the same collapse on the site question, via null === null.
    expect(naiveSameSiteIcann("data:text/html,hi", "file:///etc/passwd")).toBe(true);
  });

  it("calls one address two different origins when it is written two ways", () => {
    // WHATWG parses `0x7f000001` to `127.0.0.1` and `[0:0:0:0:0:0:0:1]` to
    // `[::1]`, so both pairs are one origin. `effectiveHost` keeps the spelling.
    expect(naiveSameOrigin("http://0x7f000001/", "http://127.0.0.1/")).toBe(false);
    expect(naiveSameOrigin("http://[::1]/", "http://[0:0:0:0:0:0:0:1]/")).toBe(false);
  });

  it("cannot separate two tenants of one multi-tenant platform at all", () => {
    // The PRIVATE-inclusive question `parsed` does not carry: `github.io` is a
    // PSL PRIVATE-section suffix, and `parsed.registrableDomain` is bound to
    // the ICANN-only view (architecture §6.1), so two unrelated tenants share a
    // registrable domain and no field on `parsed` distinguishes them.
    expect(naiveSameSiteIcann("https://alice.github.io/", "https://mallory.github.io/")).toBe(
      true,
    );
    expect(parsedOf("https://alice.github.io/").registrableDomain).toBe("github.io");
    expect(parsedOf("https://mallory.github.io/").registrableDomain).toBe("github.io");
  });
});
