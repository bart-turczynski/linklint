import { describe, expect, it } from "vitest";
import { inspect, type InspectOptions } from "../src/index.js";
import { toAscii } from "../src/unicode/idna.js";
import { skeleton } from "../src/unicode/skeleton.js";
import { analyzeHost } from "../src/parse/psl.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const cp = (...cps: number[]): string => String.fromCodePoint(...cps);

// Cyrillic homoglyphs of Latin letters (single-script — no script mixing).
const CYR = { a: 0x0430, c: 0x0441, e: 0x0435, h: 0x04bb, i: 0x0456, d: 0x0501, o: 0x043e, p: 0x0440, s: 0x0455, x: 0x0445 } as const;

// сһаѕе.com — all-Cyrillic look-alike of the BRAND chase.com.
const CYR_CHASE = `https://${cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e)}.com`;
// ассеѕѕ.com — all-Cyrillic look-alike of the NON-brand word "access".
const CYR_ACCESS = `https://${cp(CYR.a, CYR.c, CYR.c, CYR.e, CYR.s, CYR.s)}.com`;

describe("homograph_latin_skeleton — target-less whole-label homograph (pure-ASCII skeleton)", () => {
  it("fires on a NON-brand all-Cyrillic host whose skeleton folds to pure Latin", () => {
    // The defining case: no brand watchlist match, yet the host masquerades as
    // the ASCII word 'access'. Only the target-less detector catches this.
    expect(codes(CYR_ACCESS)).toContain("homograph_latin_skeleton");
    expect(codes(CYR_ACCESS)).not.toContain("homograph_skeleton_collision");
  });

  it("is a BLOCKER (weight 1.0) and lands critical on its own", () => {
    const r = inspect(CYR_ACCESS);
    const reason = r.reasons.find((x) => x.code === "homograph_latin_skeleton")!;
    expect(reason.weight).toBe(1);
    expect(r.severity).toBe("critical");
  });

  it("stacks with homograph_skeleton_collision on a brand homograph", () => {
    const c = codes(CYR_CHASE);
    expect(c).toContain("homograph_latin_skeleton"); // blocks
    expect(c).toContain("homograph_skeleton_collision"); // adds brand attribution
    expect(inspect(CYR_CHASE).severity).toBe("critical");
  });

  it("a single-script homograph does NOT fire mixed_script", () => {
    expect(codes(CYR_ACCESS)).not.toContain("mixed_script");
  });
});

describe("homograph_latin_skeleton — precision negatives (genuine non-Latin retains a non-ASCII skeleton)", () => {
  const benign = [
    `https://${cp(0x043f, 0x0440, 0x0438, 0x043c, 0x0435, 0x0440)}.com`, // пример.com (RU 'example')
    `https://${cp(0x0440, 0x043e, 0x0441, 0x0441, 0x0438, 0x044f)}.com`, // россия.com (RU 'russia')
    "https://münchen.de", // German ü IDN
    "https://straße.de", // German ß IDN
    `https://${cp(0x65e5, 0x672c, 0x8a9e)}.jp`, // 日本語.jp
    "https://example.com", // pure ASCII — never a cross-script homograph
    "https://g00gle.com", // ASCII digit-fold belongs to ascii_homoglyph/brand_homoglyph
    "http://127.0.0.1/", // IP host
    "", // unparseable
  ];
  for (const input of benign) {
    it(`does not fire for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("homograph_latin_skeleton");
    });
  }

  // Regression: LINK-iyseozhh. The detector read the registrable domain as
  // written, so a punycode (xn--) host — pure ASCII in that form — failed the
  // non-ASCII guard and scored 0.00 while its Unicode twin scored critical.
  describe("punycode parity — presentation must not change the verdict", () => {
    const parity = [
      [CYR_ACCESS, "ассеѕѕ.com (non-brand)"],
      [CYR_CHASE, "сһаѕе.com (brand)"],
      // аррӏе.com — all-Cyrillic apple.com, the case that scored info 0.00.
      [`https://${cp(CYR.a, CYR.p, CYR.p, 0x04cf, CYR.e)}.com`, "аррӏе.com"],
    ] as const;

    for (const [unicodeUrl, label] of parity) {
      it(`scores ${label} identically in Unicode and punycode form`, () => {
        const ace = `https://${toAscii(new URL(unicodeUrl).hostname)}`;
        expect(ace).toContain("xn--"); // the fixture really is punycode
        const u = inspect(unicodeUrl, { idnPolicy: "allow" });
        const a = inspect(ace, { idnPolicy: "allow" });
        expect(a.reasons.map((r) => r.code)).toEqual(u.reasons.map((r) => r.code));
        expect(a.score).toBe(u.score);
        expect(a.severity).toBe(u.severity);
        expect(a.reasons.map((r) => r.code)).toContain("homograph_latin_skeleton");
      });
    }

    it("names both the ACE and decoded form in the detail", () => {
      const d = inspect("https://xn--80ak6aa92e.com", { idnPolicy: "allow" }).reasons.find(
        (r) => r.code === "homograph_latin_skeleton",
      )?.detail;
      expect(d).toContain("xn--80ak6aa92e.com");
      expect(d).toContain("аррӏе.com");
    });

    it("leaves a genuine punycode IDN alone", () => {
      // xn--mnchen-3ya.de = münchen.de — a real German word, not a homograph.
      expect(codes("https://xn--mnchen-3ya.de")).not.toContain("homograph_latin_skeleton");
    });

    it("leaves a malformed ACE label to punycode_malformed", () => {
      // toUnicode falls back to the ASCII input, which fails the non-ASCII guard.
      expect(codes("https://xn--a.com")).not.toContain("homograph_latin_skeleton");
    });
  });

  it("does not fire on a fullwidth-Latin compatibility homograph (owned by idna_mapping_ambiguity)", () => {
    // ｇｏｏｇｌｅ.com — fullwidth Latin NFKC-folds to pure ASCII; excluded by the
    // post-NFKC non-ASCII guard so the two detectors don't overlap.
    const fullwidth = `https://${cp(0xff47, 0xff4f, 0xff4f, 0xff47, 0xff4c, 0xff45)}.com`;
    expect(codes(fullwidth)).not.toContain("homograph_latin_skeleton");
  });
});

// ---------------------------------------------------------------------------
// LINK-ubzfajzm — the public suffix is evaluated as a homograph target.
// ---------------------------------------------------------------------------

const ALLOW: InspectOptions = { idnPolicy: "allow" };

/**
 * Real IANA IDN public suffixes, built from codepoints so a reviewer can see
 * that every character below is Cyrillic and none of it is Latin. The ACE form
 * is the identity these actually have in the pinned PSL.
 */
const BG = cp(0x0431, 0x0433); //         бг  — Bulgaria      (xn--90ae)
const SRB = cp(0x0441, 0x0440, 0x0431); // срб — Serbia        (xn--90a3ac)
const ORG_CYR = cp(0x043e, 0x0440, 0x0433); // орг — Cyrillic .org (xn--c1avg)
const RUS = cp(0x0440, 0x0443, 0x0441); // рус — .rus          (xn--p1acf)
const OBR_SRB = `${cp(0x043e, 0x0431, 0x0440)}.${SRB}`; // обр.срб (xn--90azh.xn--90a3ac)

/**
 * The complete set of ICANN public suffixes in the pinned `tldts@7.4.10` whose
 * Unicode form skeletons to pure ASCII — enumerated, not sampled, by walking
 * every one of the 7,387 ICANN rules in the bundled trie and running each
 * through `skeleton(toUnicode(rule))`. 446 of those rules carry an `xn--`
 * label; exactly these 16 fold away entirely, and each one used to take its
 * WHOLE namespace to `critical` under the plain registrable-domain predicate.
 *
 * Note what the second column shows: only four of the sixteen fold to something
 * containing a digit, so a guard that merely required ASCII *letters* would
 * still have blocked the other twelve — the ten Norwegian municipal suffixes
 * fold through `æ -> ae`, which is ASCII letters throughout. That is why the
 * shipped fix is the suffix exclusion and not the letters guard.
 */
const ASCII_FOLDING_SUFFIXES: readonly (readonly [string, string])[] = [
  [SRB, "cp6"],
  [BG, "6r"],
  [OBR_SRB, "o6p.cp6"],
  ["bærum.no", "baerum.no"],
  [ORG_CYR, "opr"],
  [`${ORG_CYR}.${SRB}`, "opr.cp6"],
  ["fræna.no", "fraena.no"],
  ["hægebostad.no", "haegebostad.no"],
  ["klæbu.no", "klaebu.no"],
  ["kvæfjord.no", "kvaefjord.no"],
  ["kvænangen.no", "kvaenangen.no"],
  ["lærdal.no", "laerdal.no"],
  [RUS, "pyc"],
  ["rælingen.no", "raelingen.no"],
  ["træna.no", "traena.no"],
  ["tysvær.no", "tysvaer.no"],
];

describe("LINK-ubzfajzm — a public suffix is not a registrant's disguise", () => {
  it("the enumerated suffix list is really 16 real ICANN public suffixes", () => {
    // Guards the fixture itself: if a `tldts` re-pin retires one of these rules
    // the list below stops measuring what its comment says it measures.
    expect(ASCII_FOLDING_SUFFIXES.length).toBe(16);
    for (const [suffix, folded] of ASCII_FOLDING_SUFFIXES) {
      expect(skeleton(suffix).normalize("NFC"), suffix).toBe(folded);
      expect(analyzeHost(`registrant.${suffix}`).publicSuffix, suffix).toBe(suffix);
    }
  });

  it.each(ASCII_FOLDING_SUFFIXES.map(([suffix]) => suffix))(
    "an ordinary ASCII registrant label under '%s' is quiet",
    (suffix) => {
      const r = inspect(`https://registrant.${suffix}/`, ALLOW);
      expect(r.reasons.map((x) => x.code)).not.toContain("homograph_latin_skeleton");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    },
  );

  it.each([
    `google.${BG}`,
    `sofia.${BG}`,
    `nic.${SRB}`,
    `shop.${ORG_CYR}`,
    `news.${RUS}`,
    "kommune.bærum.no",
  ])("the named national host %s is quiet", (host) => {
    const r = inspect(`https://${host}/`, ALLOW);
    expect(r.reasons.map((x) => x.code)).not.toContain("homograph_latin_skeleton");
    expect(r.score).toBe(0);
    // Under the default IDN policy it still reads `high` on `idn_host` alone —
    // a policy signal, not a homograph verdict.
    expect(inspect(`https://${host}/`).severity).toBe("high");
  });

  it("правителство.бг does NOT fire — its own label keeps a non-ASCII skeleton", () => {
    // Filed on the issue as a casualty; it is not one. The Bulgarian government
    // host carries в/и/т/л/ь, none of which has a Latin confusable, so the
    // registrable domain skeletons to 'пpaвитeлcтвo.6r' and the ASCII guard
    // rejects it before the suffix is ever reached. It scores on `idn_host`
    // alone. Pinned so the correction is not re-lost.
    const host = `${cp(0x043f, 0x0440, 0x0430, 0x0432, 0x0438, 0x0442, 0x0435, 0x043b, 0x044c, 0x0441, 0x0442, 0x0432, 0x043e)}.${BG}`;
    expect(codes(`https://${host}/`)).not.toContain("homograph_latin_skeleton");
    expect(inspect(`https://${host}/`, ALLOW).score).toBe(0);
    expect(inspect(`https://${host}/`).severity).toBe("high"); // idn_host only
  });

  describe("true positives that must survive any narrowing", () => {
    const CYR_COP = cp(CYR.c, CYR.o, CYR.p); // сор -> cop, the documented residual
    it.each([
      [CYR_CHASE.replace("https://", ""), "brand homograph under an ASCII TLD"],
      [CYR_ACCESS.replace("https://", ""), "non-brand homograph under an ASCII TLD"],
      [`p${cp(CYR.a)}ypal.com`, "one-character Cyrillic swap in a brand"],
      [`${CYR_COP}.com`, "short all-Cyrillic word folding to ASCII"],
      [`${CYR_COP}.${BG}`, "the same, under a Cyrillic ccTLD — the registrant label is still a fold"],
      [`${cp(CYR.c, CYR.h, CYR.a, CYR.s, CYR.e)}.bærum.no`, "brand homograph under a Norwegian municipal suffix"],
      [`${BG}.com`, "a Cyrillic label folding to a DIGIT ('6r') — an ASCII-letters guard would drop this"],
      [`${cp(0x0430, 0x14bf)}.com`, "a2.com via U+14BF — likewise digit-folding"],
    ])("%s still fires (%s)", (host) => {
      expect(codes(`https://${host}/`), host).toContain("homograph_latin_skeleton");
    });
  });

  describe("no widening — a genuine non-Latin word stays quiet", () => {
    // §6.2's LINK-tydjfmci trap in the opposite direction: a narrowing must not
    // be smuggled in as a re-scoping that starts firing on ordinary vocabulary.
    // Every host here keeps a non-ASCII codepoint in its skeleton today.
    it.each([
      `${cp(0x0433, 0x043e, 0x0440, 0x0430)}.${cp(0x0440, 0x0444)}`, // гора.рф
      `${cp(0x0440, 0x0435, 0x0441, 0x0443, 0x0440, 0x0441)}.${cp(0x0440, 0x0444)}`, // ресурс.рф
      `${cp(0x0448, 0x043a, 0x043e, 0x043b, 0x0430)}.${cp(0x0440, 0x0444)}`, // школа.рф
      `${cp(0x043c, 0x0438, 0x0440)}.${ORG_CYR}`, // мир.орг — Cyrillic word AND Cyrillic TLD
      "þingvellir.is",
      "straße.de",
    ])("%s stays quiet", (host) => {
      const r = inspect(`https://${host}/`, ALLOW);
      expect(r.reasons.map((x) => x.code), host).not.toContain("homograph_latin_skeleton");
      expect(r.score, host).toBe(0);
    });
  });
});
