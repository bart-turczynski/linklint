import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { turkishLowercase } from "../src/detectors/locale-case-collapse.js";

/**
 * `locale_case_ambiguity` / `brand_locale_collapse` (LINK-ynsgmybj).
 *
 * Covers the ASCII-COLLAPSE direction of the locale-tailored case mapping class:
 * a host carrying a character that a tr/az lowercase erases into a plain ASCII
 * letter, so a validator under an ambient Turkish locale approves a different
 * domain than the request reaches. Background: docs/locale-case-mapping.md.
 */

const DOTTED_I = String.fromCodePoint(0x0130); // İ
const DOTLESS_I = String.fromCodePoint(0x0131); // ı
const COMBINING_DOT = String.fromCodePoint(0x0307);

function codes(url: string, options?: Parameters<typeof inspect>[1]): string[] {
  const result = inspect(url, options);
  expect(result.status).toBe("ok");
  return result.reasons.map((r) => r.code);
}

const ALLOW_IDN = { idnPolicy: "allow" } as const;

describe("turkishLowercase models only the rules that affect the collapse", () => {
  it("collapses the precomposed İ to a plain ASCII i", () => {
    expect(turkishLowercase(`t${DOTTED_I}ktok.com`)).toBe("tiktok.com");
  });

  it("collapses the decomposed I + U+0307 to i (the After_I rule)", () => {
    expect(turkishLowercase(`I${COMBINING_DOT}nstagram.com`)).toBe("instagram.com");
  });

  it("maps a bare ASCII I to dotless ı, so it is NOT an ASCII collapse", () => {
    expect(turkishLowercase("WIKI.com")).toBe(`w${DOTLESS_I}k${DOTLESS_I}.com`);
  });

  it("leaves every other character to the locale-independent default mapping", () => {
    expect(turkishLowercase("MÜNCHEN.DE")).toBe("münchen.de");
    expect(turkishLowercase("Пример.COM")).toBe("пример.com");
  });

  // Guards the loop's index bookkeeping: the After_I branch consumes two units.
  it("handles a trailing I and repeated collapses without dropping characters", () => {
    expect(turkishLowercase("ABCI")).toBe(`abc${DOTLESS_I}`);
    expect(turkishLowercase(`${DOTTED_I}${DOTTED_I}${DOTTED_I}`)).toBe("iii");
    expect(turkishLowercase(`I${COMBINING_DOT}I${COMBINING_DOT}x`)).toBe("iix");
  });

  // It must agree with ICU where ICU is available. The detector does not CALL
  // toLocaleLowerCase (see the module docstring), but it must not diverge from it.
  it("agrees with the platform tr/az tailoring on the collapse inputs", () => {
    for (const s of [`t${DOTTED_I}ktok.com`, `I${COMBINING_DOT}nstagram.com`, "WIKI.com", "MÜNCHEN.DE"]) {
      expect(turkishLowercase(s)).toBe(s.toLocaleLowerCase("tr"));
      expect(turkishLowercase(s)).toBe(s.toLocaleLowerCase("az"));
    }
  });
});

describe("brand_locale_collapse — the collapsed form is exactly a brand", () => {
  it("fires on the precomposed İ spelling and raises the score", () => {
    const result = inspect(`https://t${DOTTED_I}ktok.com/`);
    expect(result.status).toBe("ok");
    expect(result.reasons.map((r) => r.code)).toContain("brand_locale_collapse");
    // Escalates above the bare idn_host (0.7) baseline.
    expect(result.score).toBeGreaterThan(0.7);
  });

  it("fires on the decomposed I + U+0307 spelling of the same attack", () => {
    expect(codes(`https://I${COMBINING_DOT}nstagram.com/`)).toContain("brand_locale_collapse");
  });

  it("still fires when the caller has allowed IDNs (it is not an idn_host artifact)", () => {
    const result = inspect(`https://t${DOTTED_I}ktok.com/`, ALLOW_IDN);
    expect(result.status).toBe("ok");
    const reasons = result.reasons.map((r) => r.code);
    expect(reasons).toContain("brand_locale_collapse");
    expect(reasons).not.toContain("idn_host");
    expect(result.severity).toBe("medium"); // the 0.5 signal standing alone
  });

  it("names both the brand and the domain the request actually reaches", () => {
    const result = inspect(`https://t${DOTTED_I}ktok.com/`);
    expect(result.status).toBe("ok");
    const detail = result.reasons.find((r) => r.code === "brand_locale_collapse")?.detail ?? "";
    expect(detail).toContain("tiktok.com");
    expect(detail).toContain("xn--tiktok-qyd.com");
  });

  it("fires on a subdomain host, keyed on the registrable domain", () => {
    expect(codes(`https://login.t${DOTTED_I}ktok.com/`)).toContain("brand_locale_collapse");
  });

  it("does not also emit the weight-0 annotation (the two are mutually exclusive)", () => {
    expect(codes(`https://t${DOTTED_I}ktok.com/`)).not.toContain("locale_case_ambiguity");
  });
});

describe("locale_case_ambiguity — collapses, but not onto a brand", () => {
  it("annotates a real Turkish word without escalating", () => {
    const result = inspect(`https://${DOTTED_I}stanbul.com/`, ALLOW_IDN);
    expect(result.status).toBe("ok");
    const reasons = result.reasons.map((r) => r.code);
    expect(reasons).toContain("locale_case_ambiguity");
    expect(reasons).not.toContain("brand_locale_collapse");
    // SC-2: İstanbul is ordinary orthography — the annotation must not score.
    expect(result.score).toBe(0);
    expect(result.severity).toBe("info");
  });

  it("reports the divergence between the validator's and the resolver's view", () => {
    const result = inspect(`https://${DOTTED_I}stanbul.com/`, ALLOW_IDN);
    expect(result.status).toBe("ok");
    const detail = result.reasons.find((r) => r.code === "locale_case_ambiguity")?.detail ?? "";
    expect(detail).toContain("istanbul.com");
    expect(detail).toContain("xn--");
  });
});

describe("precision guards (SC-2)", () => {
  it.each([
    ["https://münchen.de/", "a legitimate IDN whose ü survives the tailored mapping"],
    ["https://пример.com/", "a single-script Cyrillic IDN — no ASCII collapse"],
    ["https://日本語.jp/", "a Japanese IDN"],
    [`https://w${DOTLESS_I}k${DOTLESS_I}.com/`, "the MIRROR direction's product: ı does not collapse"],
  ])("stays silent on %s (%s)", (url) => {
    const reasons = codes(url, ALLOW_IDN);
    expect(reasons).not.toContain("locale_case_ambiguity");
    expect(reasons).not.toContain("brand_locale_collapse");
  });

  it("stays silent on pure-ASCII hosts, including uppercase ones", () => {
    // The mirror direction (I -> ı) is deliberately out of scope: a detector on
    // the input would fire on essentially every uppercase host.
    for (const url of ["https://WIKI.com/", "https://TIKTOK.com/", "https://example.com/"]) {
      const reasons = codes(url);
      expect(reasons).not.toContain("locale_case_ambiguity");
      expect(reasons).not.toContain("brand_locale_collapse");
    }
  });

  it("stays silent on the ACE form — punycode carries no case-mapping hazard", () => {
    const reasons = codes("https://xn--tiktok-qyd.com/", ALLOW_IDN);
    expect(reasons).not.toContain("locale_case_ambiguity");
    expect(reasons).not.toContain("brand_locale_collapse");
  });

  it("stays silent on IP hosts", () => {
    for (const url of ["https://192.168.1.1/", "https://[::1]/"]) {
      const reasons = inspect(url).reasons.map((r) => r.code);
      expect(reasons).not.toContain("locale_case_ambiguity");
      expect(reasons).not.toContain("brand_locale_collapse");
    }
  });

  it("does not disturb the mirror direction's existing verdict", () => {
    // wıkı.com must still be caught the way it always was, by the skeleton path.
    expect(codes(`https://w${DOTLESS_I}k${DOTLESS_I}.com/`)).toContain("homograph_latin_skeleton");
  });
});
