import { describe, expect, it } from "vitest";

import { compareUrls } from "../src/index.js";
import { PSL_PROVENANCE } from "../src/data/psl-provenance.js";

/**
 * LINK-vycgfumd — `compareUrls()`: same origin, same site, three-state.
 *
 * The four normalizations `parse()` does NOT apply are pinned as ABSENT in
 * `parsed-origin-derivation.test.ts`; here each one is pinned as APPLIED, which
 * is the whole reason the function exists. Read the two files as a pair: the
 * first says what a caller deriving from `inspect().parsed` gets, this one says
 * what they get instead.
 */

describe("compareUrls — the four normalizations, applied", () => {
  it("elides the scheme's default port", () => {
    expect(compareUrls("https://ex.com:443/a", "https://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("http://ex.com:80/a", "http://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("ws://ex.com:80/a", "ws://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("wss://ex.com:443/a", "wss://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("ftp://ex.com:21/a", "ftp://ex.com/b").sameOrigin).toBe("same");
    // …and does not elide the OTHER scheme's default, which would be a bug.
    expect(compareUrls("https://ex.com:80/a", "https://ex.com/b").sameOrigin).toBe(
      "different",
    );
    expect(compareUrls("https://ex.com:8443/a", "https://ex.com/b").sameOrigin).toBe(
      "different",
    );
  });

  it("folds host case", () => {
    expect(compareUrls("http://EX.com/a", "http://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("http://EX.COM/a", "http://ex.com/b").sameOrigin).toBe("same");
    // Case folding is UTS-46's, not `toLowerCase()`'s: `İ` (U+0130) maps to
    // `i̇` and encodes, rather than lower-casing to a bare ASCII `i`.
    expect(compareUrls("http://İ.com/a", "http://i.com/b").sameOrigin).toBe("different");
  });

  it("drops a single trailing root label", () => {
    expect(compareUrls("https://ex.com./a", "https://ex.com/b").sameOrigin).toBe("same");
    expect(compareUrls("https://ex.com./a", "https://ex.com./b").sameOrigin).toBe("same");
    expect(compareUrls("https://ex.com./a", "https://ex.com/b").sameSite).toBe("same");
  });

  it("reconciles the A-label and U-label spellings of one host", () => {
    const idn = compareUrls("https://münchen.de/a", "https://xn--mnchen-3ya.de/b");
    expect(idn.sameOrigin).toBe("same");
    expect(idn.sameSite).toBe("same");
    expect(idn.sameSiteIcann).toBe("same");
    expect(idn.left.host).toBe("xn--mnchen-3ya.de");
    expect(idn.right.host).toBe("xn--mnchen-3ya.de");
    // Case folding and the IDN reconciliation compose in one step.
    expect(compareUrls("https://MÜNCHEN.de/", "https://xn--mnchen-3ya.de/").sameOrigin).toBe(
      "same",
    );
    // And two genuinely different IDNs stay different.
    expect(compareUrls("https://münchen.de/", "https://köln.de/").sameOrigin).toBe(
      "different",
    );
  });

  it("applies all four at once", () => {
    expect(compareUrls("https://MÜNCHEN.de.:443/a", "https://xn--mnchen-3ya.de/b").sameOrigin).toBe(
      "same",
    );
  });
});

describe("compareUrls — opaque origins are DETERMINATELY different, not unknown", () => {
  it.each([
    ["data:text/html,hi", "data:text/html,hi"],
    ["file:///etc/passwd", "file:///etc/passwd"],
    ["about:blank", "about:blank"],
    ["javascript:alert(1)", "javascript:alert(1)"],
    ["mailto:a@ex.com", "mailto:a@ex.com"],
  ])("two parses of %s are two origins", (left, right) => {
    const result = compareUrls(left, right);
    expect(result.sameOrigin).toBe("different");
    expect(result.sameOrigin).not.toBe("undetermined");
    expect(result.left.originKind).toBe("opaque");
  });

  it("gives an opaque origin no site either, and says so determinately", () => {
    const result = compareUrls("data:text/html,hi", "file:///etc/passwd");
    expect(result.sameSite).toBe("different");
    expect(result.sameSiteIcann).toBe("different");
    expect(result.left.site).toBeNull();
  });

  it("an opaque origin is different from a tuple origin, not unknown", () => {
    expect(compareUrls("data:text/html,hi", "https://ex.com/").sameOrigin).toBe("different");
    expect(compareUrls("file:///a", "https://ex.com/").sameSite).toBe("different");
  });

  it("keeps `undetermined` for the case that really is unknown", () => {
    for (const bad of ["ht!tp://%%%not a url", ""]) {
      const result = compareUrls(bad, "https://ex.com/");
      expect(result.sameOrigin, bad).toBe("undetermined");
      expect(result.sameSite, bad).toBe("undetermined");
      expect(result.sameSiteIcann, bad).toBe("undetermined");
      expect(result.left.originKind, bad).toBe("undetermined");
    }
  });

  it("a bare authority has a site but no determinable origin", () => {
    const result = compareUrls("ex.com/a", "https://ex.com/b");
    expect(result.sameOrigin).toBe("undetermined");
    expect(result.sameSite).toBe("same");
    expect(result.sameSiteIcann).toBe("same");
    expect(result.left.scheme).toBeNull();
    expect(result.left.host).toBe("ex.com");
  });

  it("a scheme-relative reference does not parse here at all", () => {
    // linklint's parser rejects `//host` outright, so this is the plain
    // did-not-parse case rather than the schemeless one above.
    const result = compareUrls("//ex.com/a", "https://ex.com/b");
    expect(result.sameOrigin).toBe("undetermined");
    expect(result.sameSite).toBe("undetermined");
    expect(result.left.host).toBeNull();
  });

  it("is total: a non-string argument is `undetermined`, not a TypeError", () => {
    for (const bad of [null, undefined, 42, {}, [], Symbol("x")]) {
      const result = compareUrls(bad as unknown as string, "https://ex.com/");
      expect(result.sameOrigin).toBe("undetermined");
      expect(result.left.input).toBeNull();
    }
  });
});

describe("compareUrls — IP literals are compared as addresses, not as strings", () => {
  it("canonicalizes an obfuscated IPv4", () => {
    expect(compareUrls("http://0x7f000001/a", "http://127.0.0.1/b").sameOrigin).toBe("same");
    expect(compareUrls("http://2130706433/a", "http://127.0.0.1/b").sameOrigin).toBe("same");
    expect(compareUrls("http://0x7f000001/a", "http://127.0.0.2/b").sameOrigin).toBe(
      "different",
    );
  });

  it("canonicalizes an expanded IPv6", () => {
    expect(compareUrls("http://[::1]/a", "http://[0:0:0:0:0:0:0:1]/b").sameOrigin).toBe(
      "same",
    );
    expect(compareUrls("http://[::1]/a", "http://[::2]/b").sameOrigin).toBe("different");
  });

  it("gives an IP literal a site of its own address, not a shared null", () => {
    const same = compareUrls("http://0x7f000001/", "http://127.0.0.1/");
    expect(same.sameSite).toBe("same");
    expect(same.left.site).toBe("127.0.0.1");
    // Two DIFFERENT addresses are not one site, which a null-vs-null
    // registrable-domain comparison would have called `same`.
    expect(compareUrls("http://127.0.0.1/", "http://10.0.0.1/").sameSite).toBe("different");
    expect(compareUrls("http://127.0.0.1/", "http://10.0.0.1/").sameSiteIcann).toBe(
      "different",
    );
  });
});

describe("compareUrls — the PRIVATE-inclusive site view is the point", () => {
  it.each([
    ["alice.github.io", "mallory.github.io"],
    ["good.myshopify.com", "evil.myshopify.com"],
    ["a.vercel.app", "b.vercel.app"],
  ])("separates two tenants of %s / %s", (left, right) => {
    const result = compareUrls(`https://${left}/`, `https://${right}/`);
    expect(result.sameSite).toBe("different");
    // …while the ICANN-only view — the one `parsed.registrableDomain` reports —
    // calls them one site. That disagreement is the whole content here.
    expect(result.sameSiteIcann).toBe("same");
  });

  it("agrees with the ICANN view when no PRIVATE suffix is involved", () => {
    const result = compareUrls("https://a.ex.com/", "https://b.ex.com/");
    expect(result.sameSite).toBe("same");
    expect(result.sameSiteIcann).toBe("same");
    expect(result.sameOrigin).toBe("different");
  });

  it("reports the same tenant as one site under both views", () => {
    const result = compareUrls("https://alice.github.io/x", "https://alice.github.io/y");
    expect(result.sameSite).toBe("same");
    expect(result.sameSiteIcann).toBe("same");
    expect(result.left.site).toBe("alice.github.io");
    expect(result.left.siteIcann).toBe("github.io");
  });

  it("is schemeless: http and https are one site and two origins", () => {
    const result = compareUrls("http://ex.com/", "https://ex.com/");
    expect(result.sameSite).toBe("same");
    expect(result.sameOrigin).toBe("different");
  });

  it("gives a host with no registrable domain a site of its own", () => {
    // `localhost` carries no PSL suffix under either view, so falling back to
    // the host keeps two such hosts from meeting through a shared null.
    expect(compareUrls("http://a.localhost/", "http://b.localhost/").sameSite).toBe(
      "different",
    );
    expect(compareUrls("http://localhost/x", "http://localhost/y").sameSite).toBe("same");
  });
});

describe("compareUrls — result contract", () => {
  it("carries the PSL snapshot provenance both site answers were computed on", () => {
    const result = compareUrls("https://a.ex.com/", "https://b.ex.com/");
    expect(result.pslSnapshot.date).toBe(PSL_PROVENANCE.pslListDate);
    // One-directional by construction: `pslOutdated()` returns `false` only for
    // a `dateKind` of "exact", and the shipped record is a release proxy. So
    // this field can prove staleness and cannot prove freshness, on any clock.
    expect(result.pslSnapshot.stale).not.toBe(false);
    expect(PSL_PROVENANCE.dateKind).toBe("release-proxy");
  });

  it("reports the canonical view each side was compared on", () => {
    const result = compareUrls("https://MÜNCHEN.de.:443/a?q#f", "https://ex.com:8443/");
    expect(result.left).toEqual({
      input: "https://MÜNCHEN.de.:443/a?q#f",
      scheme: "https",
      originKind: "tuple",
      host: "xn--mnchen-3ya.de",
      port: null,
      site: "xn--mnchen-3ya.de",
      siteIcann: "xn--mnchen-3ya.de",
    });
    expect(result.right.port).toBe(8443);
  });

  it("ignores everything below the authority", () => {
    const result = compareUrls(
      "https://ex.com/one?a=1#top",
      "https://ex.com/two?b=2#bottom",
    );
    expect(result.sameOrigin).toBe("same");
    expect(result.sameSite).toBe("same");
  });

  it("is symmetric and deterministic", () => {
    const pairs: [string, string][] = [
      ["https://ex.com:443/", "https://EX.com./"],
      ["https://alice.github.io/", "https://mallory.github.io/"],
      ["data:text/html,x", "data:text/html,x"],
      ["ht!tp://%%%not a url", "https://ex.com/"],
      ["http://0x7f000001/", "http://127.0.0.1/"],
    ];
    for (const [a, b] of pairs) {
      const forward = compareUrls(a, b);
      const backward = compareUrls(b, a);
      expect(forward.sameOrigin, `${a} vs ${b}`).toBe(backward.sameOrigin);
      expect(forward.sameSite, `${a} vs ${b}`).toBe(backward.sameSite);
      expect(forward.sameSiteIcann, `${a} vs ${b}`).toBe(backward.sameSiteIcann);
      expect(compareUrls(a, b)).toEqual(forward);
    }
  });

  it("does not read the userinfo as authority", () => {
    // The `inspect()` case that motivates the whole package: the host is
    // `evil.com`, and a comparison must agree.
    const result = compareUrls("https://paypal.com@evil.com/login", "https://evil.com/x");
    expect(result.sameOrigin).toBe("same");
    expect(compareUrls("https://paypal.com@evil.com/", "https://paypal.com/").sameOrigin).toBe(
      "different",
    );
  });
});
