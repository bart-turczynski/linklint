import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-lquravtj (T2.5) — COMMIT 1 of 2. This file pins the gap OPEN.
//
// Every host below is a well-formed ACE label that decodes cleanly and is still
// not registrable under RFC 5892 (IDNA2008). As of this commit linklint says
// nothing about any of them: score 0.00, severity `info`, and the only reason
// present is the weight-0 `normalization_delta` that every IDN trips.
//
// `punycode_malformed` covers strictly less and does not reach these: it fires
// when an `xn--` label fails to DECODE. These decode. That is the whole point —
// the raw Unicode spellings never survive `parse()`'s host-character rule (a
// bare heart or a middle dot returns `invalid`), and a raw ZWNJ is already
// `invisible_char` at weight 1, so the ACE spelling is the form that travels.
//
// The next commit registers `idna_protocol_violation` and turns each of these
// assertions red, then rewrites it. The diff carries the before and the after.

/** Well-formed ACE, decodes cleanly, DISALLOWED / CONTEXT* under RFC 5892. */
const VIOLATING_HOSTS: ReadonlyArray<readonly [string, string, string]> = [
  ["xn--g6h.example.com", "♥.example.com", "U+2665, DISALLOWED symbol"],
  ["xn--abcd-176a.example.com", "ab‌cd.example.com", "ZWNJ, CONTEXTJ A.1"],
  ["xn--abcd-676a.example.com", "ab‍cd.example.com", "ZWJ, CONTEXTJ A.2"],
  ["xn--ab-0ea.example.com", "a·b.example.com", "middle dot, CONTEXTO A.3"],
  ["xn--abcd-cx4c.example.com", "ab・cd.example.com", "katakana middle dot, CONTEXTO A.7"],
  ["xn--1ca20iaaaa.example.com", "á́́́́́.example.com", "6 stacked combining marks"],
];

/**
 * Hosts that are legitimate under IDNA2008 and must stay clean of any
 * protocol-violation finding in BOTH commits. These are the false-positive
 * controls, and they are the assertions that do NOT change.
 */
const LEGITIMATE_HOSTS: ReadonlyArray<readonly [string, string]> = [
  ["xn--11b2ezcw70k.example.com", "Devanagari virama + ZWJ — the CONTEXTJ A.1 exemption"],
  ["xn--mnchen-3ya.de", "münchen.de — an ordinary German IDN"],
  ["xn--80ak6aa92e.com", "аррӏе.com — all-Cyrillic, no protocol violation"],
  ["example.com", "a plain ASCII host"],
  ["xn--caf-dma.example.com", "café — one combining-capable Latin label"],
];

describe("IDNA2008 protocol violations are NOT detected yet (LINK-lquravtj, pre-fix)", () => {
  it.each(VIOLATING_HOSTS)(
    "%s (%s — %s) scores 0.00 and carries no violation finding",
    (ace) => {
      const r = inspect(`https://${ace}/`);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).toEqual(["normalization_delta"]);
    },
  );

  it("the ACE form decodes cleanly, so punycode_malformed cannot reach it", () => {
    for (const [ace] of VIOLATING_HOSTS) {
      const codes = inspect(`https://${ace}/`).reasons.map((x) => x.code);
      expect(codes).not.toContain("punycode_malformed");
    }
  });
});

describe("mixed number systems are ALREADY covered — verified, then left alone", () => {
  // The ticket's own claim, re-derived rather than trusted. This is the one
  // member of the RFC 5892 family that already lands at 1.00, via mixed_script.
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
    expect(codes).not.toContain("idna_protocol_violation");
  });
});
