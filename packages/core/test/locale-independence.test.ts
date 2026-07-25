import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { compareReasons } from "../src/schema/reason-codes.js";
import { skeleton } from "../src/unicode/skeleton.js";
import { toAscii } from "../src/unicode/idna.js";

/**
 * Locale-independence drift-lock (LINK-aiakfzwy).
 *
 * Case mapping and collation in Unicode are LOCALE-TAILORED. Under `tr`/`az`,
 * `I` lowercases to `ı` (U+0131) and `i` uppercases to `İ` (U+0130); `lt` adds
 * combining dots. A normalization or ordering step that inherits the ambient
 * host locale therefore produces different output on a Turkish user's machine
 * than on the analyst's — silently, and invisibly to any corpus.
 *
 * linklint's contract is a deterministic, machine-independent verdict
 * (docs/architecture.md). These tests pin the two things that guarantee it:
 * that no locale-sensitive API reaches identity or ordering decisions, and that
 * the behavior is stable when the tailored mappings are applied explicitly.
 *
 * Full audit and the residual `İ` (U+0130) detection gap: docs/locale-case-mapping.md.
 */

const thisDir = dirname(fileURLToPath(import.meta.url));
// packages/core/test -> packages/core/src
const SRC_ROOT = join(thisDir, "..", "src");

function tsSources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...tsSources(full));
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

const SOURCES = tsSources(SRC_ROOT).map((path) => ({
  path,
  rel: relative(SRC_ROOT, path),
  text: readFileSync(path, "utf8"),
}));

/**
 * True if `text` contains a CALL to `method`. Matching the call shape rather
 * than the bare name lets the source discuss these APIs in comments (which the
 * fix in schema/reason-codes.ts must, to explain itself) without tripping the
 * ban on using them.
 */
function callsMethod(text: string, method: string): boolean {
  return new RegExp(String.raw`\.${method}\s*\(`).test(text);
}

describe("no locale-sensitive API reaches an identity or ordering decision", () => {
  it("finds source files to scan (guards against a silently empty sweep)", () => {
    expect(SOURCES.length).toBeGreaterThan(30);
  });

  // `toLocaleLowerCase`/`toLocaleUpperCase` apply the tr/az/lt tailorings and can
  // REWRITE a hostname ('WIKI.example.com' -> 'wıkı.example.com', a different
  // registrable domain). `String.prototype.toLowerCase` is defined by ECMA-262
  // against the Unicode Default Case Conversion with no tailoring, so it is the
  // only correct choice here — matching the WHATWG URL Standard's insistence on
  // "ASCII lowercase" rather than a Unicode lowercase for scheme and host.
  it.each(["toLocaleLowerCase", "toLocaleUpperCase"])(
    "no source file calls %s",
    (api) => {
      const offenders = SOURCES.filter((f) => callsMethod(f.text, api)).map((f) => f.rel);
      expect(offenders).toEqual([]);
    },
  );

  // `localeCompare` without an explicit locale resolves against the ambient ICU
  // locale, so equal-weight reasons sort differently on a cs/sk/az/lt/lv/th
  // machine than on an en-US one. Reason codes are ASCII `[a-z0-9_]`
  // identifiers; codepoint comparison is both correct and locale-independent.
  it("no source file calls localeCompare", () => {
    const offenders = SOURCES.filter((f) => callsMethod(f.text, "localeCompare")).map((f) => f.rel);
    expect(offenders).toEqual([]);
  });

  // Intl collators and case-aware Intl surfaces carry the same ambient-locale
  // hazard. `Intl.Collator` is the direct equivalent of the ban above.
  it("no source file constructs an Intl.Collator", () => {
    const offenders = SOURCES.filter((f) => f.text.includes("Intl.Collator")).map((f) => f.rel);
    expect(offenders).toEqual([]);
  });
});

describe("compareReasons is a locale-independent total order", () => {
  // The exact set of codes that reordered under a tailored collation when the
  // comparator was `localeCompare` (verified against Node's full-ICU build).
  const CODES = [
    "embedded_domain_in_subdomain",
    "excessive_subdomain_depth",
    "idn_host",
    "idna_mapping_ambiguity",
    "ip_cloud_metadata",
    "malware_url_listed",
    "scheme_denied",
    "separator_lookalike",
    "young_domain_brand_risk",
  ];

  const CODEPOINT_ORDER = [...CODES].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  it("orders equal-weight codes by codepoint, not by collation", () => {
    const sorted = CODES.map((code) => ({ code, weight: 0 }))
      .sort(compareReasons)
      .map((r) => r.code);
    expect(sorted).toEqual(CODEPOINT_ORDER);
  });

  // The regression itself: under these locales a collation-based tie-break
  // yields a DIFFERENT order. Pinning the divergence proves the codes are a
  // genuine witness and that the comparator no longer follows collation.
  it.each(["az", "cs", "lt", "lv", "sk", "th"])(
    "codepoint order differs from %s collation for these codes (witness is real)",
    (locale) => {
      const collated = [...CODES].sort((a, b) => a.localeCompare(b, locale));
      expect(collated).not.toEqual(CODEPOINT_ORDER);
    },
  );

  it("weight still dominates the code tie-break", () => {
    const sorted = [
      { code: "aaa", weight: 0 },
      { code: "zzz", weight: 0.9 },
    ]
      .sort(compareReasons)
      .map((r) => r.code);
    expect(sorted).toEqual(["zzz", "aaa"]);
  });
});

describe("inspect() is stable under the Turkish-I case tailorings", () => {
  // The manufactured-confusable direction: an ambient tr/az locale lowercasing
  // 'WIKI.com' produces 'wıkı.com', a DIFFERENT registrable domain. linklint
  // must not perform that mapping itself — the ASCII host stays ASCII and clean.
  it("an uppercase ASCII host is not rewritten into a dotless-i host", () => {
    const result = inspect("https://WIKI.com/");
    expect(result.status).toBe("ok");
    expect(result.parsed).not.toBeNull();
    expect(result.parsed!.registrableDomain).toBe("wiki.com");
    expect(result.reasons.map((r) => r.code)).toEqual([]);
    // Sanity: the tailored mapping really would have produced another domain.
    expect("WIKI.com".toLocaleLowerCase("tr")).toBe("wıkı.com");
  });

  // The scheme half of the same bug: 'FILE'.toLocaleLowerCase('tr') === 'fıle',
  // which matches no known scheme. linklint must still recognize the scheme.
  it("an uppercase scheme is recognized (not mangled to 'fıle'/'httpſ')", () => {
    const result = inspect("HTTPS://example.com/");
    expect(result.status).toBe("ok");
    expect(result.parsed).not.toBeNull();
    expect(result.parsed!.scheme).toBe("https");
    expect("FILE".toLocaleLowerCase("tr")).toBe("fıle"); // what we must NOT do
  });

  // U+0131 (ı) is the product of the tr/az lowercase of ASCII 'I'. It IS in the
  // UTS-39 confusables table, so the whole-label homograph fires and the host
  // scores as an impersonation rather than an ordinary IDN.
  it("a dotless-i host is caught as a Latin-skeleton homograph", () => {
    expect(skeleton("wıkı")).toBe("wiki");
    const result = inspect("https://wıkı.com/");
    expect(result.status).toBe("ok");
    expect(result.reasons.map((r) => r.code)).toContain("homograph_latin_skeleton");
  });
});

/**
 * Characterization of the residual gap, NOT an endorsement of it.
 *
 * U+0130 (İ) is the mirror image of U+0131: a tr/az lowercase collapses it to a
 * plain ASCII `i`, so a validator running under an ambient Turkish locale reads
 * `tİktok.com` as the brand `tiktok.com`, while UTS-46 — and therefore the
 * resolver — reads `xn--tiktok-qyd.com`. That is a validate-then-transform split
 * in the attacker's favor.
 *
 * UTS-39 confusables.txt 16.0.0 contains NO row for U+0130 or U+0307, so the
 * skeleton cannot fold it and no confusable-derived detector can fire. These
 * assertions pin today's behavior so that closing the gap is a visible,
 * deliberate change rather than an accident. See docs/locale-case-mapping.md.
 */
describe("KNOWN GAP: the U+0130 (İ) ASCII-collapse direction is not detected", () => {
  it("UTS-46 keeps İ distinct from i while a tr lowercase collapses it", () => {
    expect(toAscii("tİktok.com")).toBe("xn--tiktok-qyd.com");
    expect(toAscii("tiktok.com")).toBe("tiktok.com");
    // The validator's view under an ambient Turkish locale: an exact brand match.
    expect("tİktok.com".toLocaleLowerCase("tr")).toBe("tiktok.com");
  });

  it("the UTS-39 skeleton does not fold İ to i", () => {
    expect(skeleton("tİktok".toLowerCase())).not.toBe("tiktok");
  });

  it("İ-brand impersonation currently scores as an ordinary IDN", () => {
    const result = inspect("https://tİktok.com/");
    expect(result.status).toBe("ok");
    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain("idn_host");
    expect(codes).not.toContain("homograph_latin_skeleton");
    expect(codes).not.toContain("brand_lookalike");
  });
});
