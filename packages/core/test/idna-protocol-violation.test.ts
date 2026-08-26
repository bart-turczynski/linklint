import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";

// LINK-lquravtj (T2.5) — CONVERTED, not deleted. The commit before this one
// pinned the gap OPEN: each host in VIOLATING_HOSTS returned 0.00 / `info` with
// `["normalization_delta"]` as its entire reason list. All six of those
// assertions passed, and this commit turns each of them red and then rewrites
// it, so the diff carries the before and the after in one place.
//
// What these hosts have in common is the shape that actually travels: the ACE
// is WELL FORMED, it decodes cleanly, tr46 round-trips it without complaint,
// and the U-label it yields is still not registrable under RFC 5892. The raw
// Unicode spellings never get this far — a bare heart or a middle dot fails
// `parse()`'s host-character rule and returns `invalid`, and a raw ZWNJ is
// already `invisible_char` at weight 1 — so ACE is the only spelling that
// reaches a parsed detector unremarked.
//
// `punycode_malformed` covers strictly LESS and is asserted below to stay out
// of the way: it fires when an `xn--` label fails to DECODE, and these decode.
//
// The false-positive controls are UNCHANGED from the previous commit and are
// re-asserted precisely because they must not move.

const CODE = "idna_protocol_violation";

/** Well-formed ACE, decodes cleanly, not permitted under RFC 5892. */
const VIOLATING_HOSTS: ReadonlyArray<readonly [string, string, string]> = [
  ["xn--g6h.example.com", "♥.example.com", "U+2665, DISALLOWED symbol"],
  ["xn--abcd-176a.example.com", "ab‌cd.example.com", "ZWNJ, CONTEXTJ A.1"],
  ["xn--abcd-676a.example.com", "ab‍cd.example.com", "ZWJ, CONTEXTJ A.2"],
  ["xn--ab-0ea.example.com", "a·b.example.com", "middle dot, CONTEXTO A.3"],
  ["xn--abcd-cx4c.example.com", "ab・cd.example.com", "katakana middle dot, CONTEXTO A.7"],
  ["xn--1ca40idaefg.example.com", "a + 5 combining marks", "stacked combining marks"],
];

/**
 * Hosts that are legitimate under IDNA2008 and must stay clean. Each of the
 * five CONTEXTO code points appears here IN its permitted context, so the
 * detector is shown to implement the rule rather than to blocklist the
 * character.
 */
const LEGITIMATE_HOSTS: ReadonlyArray<readonly [string, string]> = [
  ["xn--11b2ezcw70k.example.com", "Devanagari virama + ZWJ — the CONTEXTJ A.1 exemption"],
  ["xn--collabora-2pa.example.com", "col·labora — Catalan l·l, the A.3 context"],
  ["xn--wva3je.example.com", "α͵β — keraia followed by Greek, the A.4 context"],
  ["xn--4dbc5h.example.com", "א׳ב — geresh after Hebrew, the A.5 context"],
  ["xn--4dbc8h.example.com", "א״ב — gershayim after Hebrew, the A.6 context"],
  ["xn--ccke4x.example.com", "ア・イ — katakana middle dot with kana, the A.7 context"],
  ["xn--8hbcd.example.com", "٠١٢ — one Arabic digit block only, so A.8/A.9 is satisfied"],
  ["xn--dmbcd.example.com", "۰۱۲ — the other block only, likewise"],
  ["xn--ting-hv5a.example.com", "tiếng — ordinary Vietnamese stacking"],
  ["xn--1ca40idaef.example.com", "a + 4 combining marks — exactly at the limit"],
  ["xn--mnchen-3ya.de", "münchen.de — an ordinary German IDN"],
  ["xn--80ak6aa92e.com", "аррӏе.com — all-Cyrillic, no protocol violation"],
  ["example.com", "a plain ASCII host"],
  ["xn--caf-dma.example.com", "café — one combining-capable Latin label"],
];

describe("IDNA2008 protocol violations are detected (LINK-lquravtj)", () => {
  it.each(VIOLATING_HOSTS)("%s (%s — %s) raises the violation at 0.35", (ace) => {
    const r = inspect(`https://${ace}/`);
    expect(r.status).toBe("ok");
    const finding = r.reasons.find((x) => x.code === CODE);
    expect(finding).toBeDefined();
    expect(finding!.weight).toBeCloseTo(0.35, 5);
    // The gap was 0.00 / `info`; it is now a scoring finding in the medium band.
    expect(r.score).toBeGreaterThanOrEqual(0.35);
    expect(r.severity).not.toBe("info");
  });

  it("names the RFC 5892 rule it applied, not merely that something was wrong", () => {
    const detailFor = (ace: string) =>
      inspect(`https://${ace}/`).reasons.find((x) => x.code === CODE)!.detail;

    expect(detailFor("xn--g6h.example.com")).toContain("U+2665");
    expect(detailFor("xn--abcd-176a.example.com")).toContain("CONTEXTJ");
    expect(detailFor("xn--ab-0ea.example.com")).toContain("A.3");
    expect(detailFor("xn--abcd-cx4c.example.com")).toContain("A.7");
    expect(detailFor("xn--1ca40idaefg.example.com")).toContain("combining marks");
  });

  it("fires on the ACE spelling — the form punycode_malformed cannot reach", () => {
    for (const [ace] of VIOLATING_HOSTS) {
      const codes = inspect(`https://${ace}/`).reasons.map((x) => x.code);
      expect(codes).toContain(CODE);
      // These labels DECODE, so the malformed-ACE detector must stay silent.
      expect(codes).not.toContain("punycode_malformed");
    }
  });

  it("covers the two RFC 5892 rules that scripts alone cannot see", () => {
    // A.8/A.9 in a PURE-ARABIC label: both digit blocks are Arabic script, so
    // mixed_script does not fire and this is genuinely new coverage.
    const digits = inspect("https://xn--8hb20a.example.com/");
    expect(digits.reasons.map((x) => x.code)).toContain(CODE);
    expect(digits.reasons.map((x) => x.code)).not.toContain("mixed_script");

    // U+0640 ARABIC TATWEEL is `Lm` — a LETTER, invisible to the
    // symbol/punctuation test, and DISALLOWED only via exception table F.4.
    const tatweel = inspect("https://xn--mgbc5e.example.com/");
    expect(tatweel.reasons.map((x) => x.code)).toContain(CODE);
    expect(tatweel.reasons.find((x) => x.code === CODE)!.detail).toContain("F.4");
  });

  it("stacks with the impersonation checks rather than replacing them", () => {
    // A keraia out of context inside a Latin label is BOTH a script mix and a
    // protocol violation; the aggregate keeps mixed_script's critical verdict.
    const r = inspect("https://xn--abcd-hdd.example.com/");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("mixed_script");
    expect(codes).toContain(CODE);
    expect(r.severity).toBe("critical");
  });
});

describe("mixed number systems are ALREADY covered — verified, then left alone", () => {
  // The ticket's own claim, re-derived rather than trusted.
  it("٠۱example.com is critical at 1.00 via mixed_script", () => {
    const r = inspect("https://٠۱example.com/");
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
    expect(r.reasons.map((x) => x.code)).toContain("mixed_script");
  });
});

describe("legitimate IDNA2008 hosts stay clean (false-positive controls)", () => {
  it.each(LEGITIMATE_HOSTS)("%s (%s) raises no protocol-violation finding", (host) => {
    const codes = inspect(`https://${host}/`).reasons.map((x) => x.code);
    expect(codes).not.toContain(CODE);
  });

  it("the combining-mark limit is a run limit, and 4 is inside it", () => {
    // The boundary, both sides, so the threshold is pinned rather than implied.
    expect(inspect("https://xn--1ca40idaef.example.com/").reasons.map((x) => x.code)).not.toContain(
      CODE,
    );
    expect(inspect("https://xn--1ca40idaefg.example.com/").reasons.map((x) => x.code)).toContain(
      CODE,
    );
  });

  it("an IP literal and an empty host are never examined", () => {
    for (const url of ["https://192.168.1.1/", "https://[::1]/"]) {
      expect(inspect(url).reasons.map((x) => x.code)).not.toContain(CODE);
    }
  });
});

describe("the reason code is registered as a scoring code at its argued weight", () => {
  it("carries weight 0.35 in the registry, in the medium band", () => {
    expect(REASON_CODES[CODE].scoring).toBe(true);
    expect(REASON_CODES[CODE].weight).toBeCloseTo(0.35, 5);
    // Argued from the table: above punycode_malformed (a malformed ACE is often
    // an accident), below the smuggling primitives that misdirect a parser.
    expect(REASON_CODES[CODE].weight).toBeGreaterThan(REASON_CODES.punycode_malformed.weight);
    expect(REASON_CODES[CODE].weight).toBeLessThan(REASON_CODES.control_char.weight);
    expect(REASON_CODES[CODE].weight).toBeLessThan(REASON_CODES.separator_lookalike.weight);
  });
});
