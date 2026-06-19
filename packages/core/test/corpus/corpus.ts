import type { Severity } from "../../src/index.js";

/**
 * Labeled test corpus (NFR-TEST-1). The single shared fixture consumed by the
 * corpus conformance test (D1) and the precision/recall harness (D2).
 *
 * Conventions for adding rows (each detector slice appends its own):
 *  - `label`:
 *      "deceptive" — parsed, MUST score (severity >= `minSeverity`, default medium)
 *      "benign"    — parsed, MUST be score 0 / severity info, no info reasons needed
 *      "info"      — parsed, score 0 / severity info, carries informational reasons
 *      "invalid"   — unparseable; status "invalid" (NOT benign)
 *  - `expectReasons` — reason codes that MUST be present.
 *  - `forbidReasons` — reason codes that MUST NOT be present.
 *  - Build invisible/bidi inputs from codepoints so this file stays readable.
 */
export type CorpusLabel = "deceptive" | "benign" | "info" | "invalid";

export interface CorpusRow {
  input: string;
  label: CorpusLabel;
  /** Minimum severity band for deceptive rows (default "medium"). */
  minSeverity?: Severity;
  expectReasons?: string[];
  forbidReasons?: string[];
  notes?: string;
  source?: string;
}

const ZWSP = String.fromCodePoint(0x200b);
const RLO = String.fromCodePoint(0x202e);
const CYR_A = String.fromCodePoint(0x0430); // а
const SOFT_HYPHEN = String.fromCodePoint(0x00ad);

export const CORPUS: CorpusRow[] = [
  // ── Deceptive: canonical scoring attack set (SC-1) ──────────────────────
  {
    input: "https://paypal.com@xn--pypal-4ve.ru/login",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["userinfo_present", "mixed_script"],
    notes: "PRD canonical example: userinfo spoof + Cyrillic homograph host",
  },
  {
    input: `https://p${CYR_A}ypal.com`,
    label: "deceptive",
    expectReasons: ["mixed_script"],
    notes: "script-mixed host (Latin + Cyrillic а)",
  },
  {
    input: "https://paypal.com@evil.com/login",
    label: "deceptive",
    expectReasons: ["userinfo_present"],
    notes: "userinfo authority deception",
  },
  {
    input: "http://2130706433/",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "decimal-encoded 127.0.0.1",
  },
  {
    input: "http://0x7f.0.0.1/",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "hex-encoded IP",
  },
  {
    input: "https://paypal.com.spoof.info/",
    label: "deceptive",
    expectReasons: ["embedded_domain_in_subdomain"],
    notes: "real registrable domain is spoof.info",
  },
  {
    input: "https://paypal.com.login.evil.com/",
    label: "deceptive",
    expectReasons: ["embedded_domain_in_subdomain"],
    notes: "E4: brand domain mid-subdomain (filler label after it); real domain evil.com",
  },
  {
    input: "https://login.paypal.com.account.evil.com/",
    label: "deceptive",
    expectReasons: ["embedded_domain_in_subdomain"],
    notes: "E4: brand domain wrapped by filler labels on both sides",
  },
  {
    input: "https://secure-paypal.com.cdn.evil.com/",
    label: "deceptive",
    expectReasons: ["embedded_domain_in_subdomain"],
    notes: "E4: brand-ish domain mid-subdomain (hyphenated label)",
  },
  {
    input: `https://example.com/${RLO}fdp.exe`,
    label: "deceptive",
    expectReasons: ["bidi_override"],
    notes: "RTL override in path",
  },
  {
    input: `https://exa${ZWSP}mple.com`,
    label: "deceptive",
    expectReasons: ["invisible_char"],
    notes: "zero-width space in host",
  },
  {
    input: `https://exa${SOFT_HYPHEN}mple.com`,
    label: "deceptive",
    expectReasons: ["invisible_char"],
    notes: "soft hyphen in host",
  },
  {
    input: "javascript:alert(document.cookie)",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["dangerous_scheme"],
  },
  {
    input: "data:text/html,<script>alert(1)</script>",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["dangerous_scheme"],
  },
  {
    input: "https://example.com/%2e%2e%2f%2e%2e%2fadmin",
    label: "deceptive",
    expectReasons: ["encoding_obfuscation"],
    notes: "encoded traversal",
  },

  // ── Benign (SC-2): must be score 0 / info ───────────────────────────────
  { input: "https://www.example.com/path?q=1#x", label: "benign" },
  { input: "https://github.com/anthropics/claude-code", label: "benign" },
  { input: "https://sub.domain.example.co.uk/a/b", label: "benign", forbidReasons: ["embedded_domain_in_subdomain"], notes: "deep subdomain, multi-level suffix" },
  { input: "https://cdn.assets.eu-west-1.example.com/", label: "benign", forbidReasons: ["embedded_domain_in_subdomain"], notes: "E4 guard: 3-label subdomain, no mid-window is a registrable domain" },
  { input: "https://mail.google.com/", label: "benign" },
  { input: "https://amazon.co.jp/", label: "benign" },
  { input: "192.168.1.1", label: "benign", forbidReasons: ["ip_obfuscation"], notes: "canonical IP is not obfuscation" },
  { input: "http://127.0.0.1:3000/", label: "benign", forbidReasons: ["ip_obfuscation"] },
  { input: "example.com", label: "benign", notes: "bare host, missing scheme" },
  { input: "https://example.com/?redirect=https%3A%2F%2Fok.com%2Fp", label: "benign", forbidReasons: ["encoding_obfuscation"], notes: "legitimate encoded query value" },

  // ── Informational-only (SC-1a): annotate, weight 0, benign ──────────────
  { input: "https://xn--bcher-kva.de/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script"], notes: "bücher.de ACE form" },
  { input: "https://müller.de/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script"], notes: "legitimate German IDN" },
  { input: "https://пример.com", label: "info", expectReasons: ["confusable_char", "normalization_delta"], forbidReasons: ["mixed_script"], notes: "single-script Cyrillic label + ASCII TLD" },
  { input: "https://日本語.jp/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script"], notes: "Japanese IDN" },
  { input: `https://example.com/p${CYR_A}y`, label: "info", expectReasons: ["confusable_in_path"], notes: "path-embedded confusable" },

  // ── Invalid (SC-2a): not benign ─────────────────────────────────────────
  { input: "ht!tp://%%%not a url", label: "invalid" },
  { input: "", label: "invalid" },
  { input: "   ", label: "invalid" },
  { input: "http://", label: "invalid" },
  { input: "http://exa mple.com", label: "invalid", notes: "space in host" },
  { input: "@@@@@", label: "invalid" },
];
