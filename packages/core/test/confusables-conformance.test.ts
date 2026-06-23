import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { CONFUSABLES } from "../src/data/confusables.js";

/**
 * E2 — confusables conformance against the official Unicode UTS#39 list.
 *
 * A documented, representative sample of `source -> target` mappings from
 * confusables.txt (Unicode 16.0.0): the high-risk Latin lookalikes from
 * Cyrillic/Greek, fullwidth/mathematical forms, plus a few multi-codepoint
 * targets. Each row pins the official ASCII prototype so the test fails loudly if
 * the generated table drifts (LINK-aadirory). Sampling from the same generated
 * data E1 ships keeps the fixture honest.
 */
interface OfficialMapping {
  name: string;
  /** Source codepoint (the confusable character). */
  cp: number;
  /** Official ASCII prototype it maps to. */
  target: string;
}

const FIXTURE: OfficialMapping[] = [
  // ── Cyrillic → Latin (the canonical homograph set) ──
  { name: "CYRILLIC SMALL LETTER A", cp: 0x0430, target: "a" },
  { name: "CYRILLIC SMALL LETTER IE", cp: 0x0435, target: "e" },
  { name: "CYRILLIC SMALL LETTER O", cp: 0x043e, target: "o" },
  { name: "CYRILLIC SMALL LETTER ER", cp: 0x0440, target: "p" },
  { name: "CYRILLIC SMALL LETTER ES", cp: 0x0441, target: "c" },
  { name: "CYRILLIC SMALL LETTER U", cp: 0x0443, target: "y" },
  { name: "CYRILLIC SMALL LETTER HA", cp: 0x0445, target: "x" },
  { name: "CYRILLIC SMALL LETTER DZE", cp: 0x0455, target: "s" },
  { name: "CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I", cp: 0x0456, target: "i" },
  { name: "CYRILLIC SMALL LETTER JE", cp: 0x0458, target: "j" },
  // ── Greek → Latin ──
  { name: "GREEK SMALL LETTER OMICRON", cp: 0x03bf, target: "o" },
  { name: "GREEK SMALL LETTER ALPHA", cp: 0x03b1, target: "a" },
  { name: "GREEK SMALL LETTER RHO", cp: 0x03c1, target: "p" },
  { name: "GREEK CAPITAL LETTER ALPHA", cp: 0x0391, target: "A" },
  // ── Latin-script lookalikes ──
  { name: "LATIN SMALL LETTER DOTLESS I", cp: 0x0131, target: "i" },
  { name: "LATIN SMALL LETTER ALPHA", cp: 0x0251, target: "a" },
  // ── Fullwidth / mathematical forms ──
  { name: "FULLWIDTH LATIN SMALL LETTER A", cp: 0xff41, target: "a" },
  { name: "MATHEMATICAL BOLD SMALL A", cp: 0x1d41a, target: "a" },
  // ── Multi-codepoint targets (E1 must thread char -> sequence) ──
  { name: "LATIN SMALL LETTER AE", cp: 0x00e6, target: "ae" },
  { name: "LATIN CAPITAL LETTER AE", cp: 0x00c6, target: "AE" },
  { name: "LATIN SMALL LIGATURE FI", cp: 0xfb01, target: "fi" },
  { name: "LATIN SMALL LIGATURE FFI", cp: 0xfb03, target: "ffi" },
];

describe("UTS#39 confusables conformance (E2)", () => {
  it.each(FIXTURE)("generated table maps $name to its official target", ({ cp, target }) => {
    const entry = CONFUSABLES.get(String.fromCodePoint(cp));
    expect(entry, `U+${cp.toString(16)} missing from table`).toBeDefined();
    expect(entry!.target).toBe(target);
  });

  it.each(FIXTURE)(
    "inspect() annotates $name in the path with confusable_in_path",
    ({ cp, target }) => {
      const ch = String.fromCodePoint(cp);
      const r = inspect(`https://example.com/pay${ch}ment`);
      expect(r.reasons.map((x) => x.code)).toContain("confusable_in_path");
      const hit = r.confusables.find((c) => c.char === ch && c.component === "path");
      expect(hit, `no path confusable for U+${cp.toString(16)}`).toBeDefined();
      expect(hit!.confusableWith).toContain(target);
      expect(hit!.codepoint).toBe(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    },
  );

  it("annotates a confusable character in the host with confusable_char", () => {
    // Cyrillic а embedded in an otherwise-Latin host label.
    const r = inspect(`https://p${String.fromCodePoint(0x0430)}ypal.com`);
    expect(r.reasons.map((x) => x.code)).toContain("confusable_char");
    const hit = r.confusables.find((c) => c.component === "host");
    expect(hit).toBeDefined();
    expect(hit!.confusableWith).toContain("a");
  });

  it("confusable annotation never scores on its own (FR-D-16)", () => {
    // A pure-ASCII path carrying confusables must still score 0 — confusable_in_path
    // is informational, and the host (example.com) is benign.
    const r = inspect(`https://example.com/${String.fromCodePoint(0x0440)}ay`);
    expect(r.reasons.map((x) => x.code)).toContain("confusable_in_path");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });
});

describe("E2 — SC-2 de-noising holds with the official table", () => {
  // Legitimate single-script IDNs must stay score 0 / severity info and must NOT
  // gain a score from confusable annotation (SC-1a / SC-2 / FR-D-16).
  it.each([
    { input: "https://bücher.de/", note: "German IDN (no confusable sources)" },
    { input: "https://müller.de/", note: "German IDN" },
    { input: "https://café.com/", note: "French IDN" },
    { input: `https://${"пример"}.com`, note: "single-script Cyrillic word + ASCII TLD" },
  ])("$note stays benign: $input", ({ input }) => {
    // idnPolicy "allow" isolates the DECEPTION analysis: these legit IDNs would
    // otherwise be blocked by the default idn_host policy signal (not a confusable
    // false-positive). This test is about confusable de-noising (SC-2).
    const r = inspect(input, { idnPolicy: "allow" });
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons.map((x) => x.code)).not.toContain("mixed_script");
  });
});
