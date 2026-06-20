import type { Severity } from "../../src/index.js";
import { VECTORS } from "./vectors.js";

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
  {
    input: "https://xn--abc.com/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["punycode_malformed"],
    notes: "E5: undecodable ACE label (tr46 error)",
  },
  {
    input: "https://xn--.com/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["punycode_malformed"],
    notes: "E5: empty ACE payload",
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
  { input: "https://xn--bcher-kva.de/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script", "punycode_malformed"], notes: "bücher.de ACE form" },
  { input: "https://XN--CAF-DMA.com/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["punycode_malformed"], notes: "E5 guard: uppercase ACE round-trips to café — NOT malformed" },
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

  // ── Epic J: parser-differential & structural-obfuscation (J1–J9) ────────
  // Deceptive — authority ambiguity (J1, weight 0.65 → high)
  {
    input: "http://foo@evil.com:80@google.com/",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["ambiguous_authority"],
    notes: "J1 multiple_userinfo — parses ok, real host is google.com",
  },
  {
    input: "http://google.com#@evil.com/",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["ambiguous_authority"],
    notes: "J1 fragment_in_authority (#@)",
  },
  {
    input: "http://target.com/////evil.com",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["ambiguous_authority"],
    notes: "J1 slash_confusion — network-path reference (CVE-2021-23435)",
  },

  // Deceptive — separator look-alikes (J2, weight 0.5 → medium)
  {
    input: "https://github.com∕x@evil.zip",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["separator_lookalike"],
    notes: "J2 division-slash lure — real host evil.zip (also userinfo + .zip)",
  },
  {
    input: "https://example.com／a@host.example/",
    label: "deceptive",
    expectReasons: ["separator_lookalike"],
    notes: "J2 fullwidth-solidus lure pushes the brand into userinfo",
  },

  // Deceptive — control-char / CRLF smuggling (J3, weight 0.6 → high)
  {
    input: "http://127.0.0.1:6379/%0D%0ASLAVEOF",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["control_char"],
    notes: "J3 encoded CRLF — Redis SLAVEOF smuggling",
  },
  {
    input: "http://127.0.0.1%09foo.google.com",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["control_char"],
    notes: "J3 encoded TAB host terminator",
  },
  {
    input: "http://example.com/%250D%250Aevil",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["control_char"],
    notes: "J3 double-encoded CRLF (%250D%250A)",
  },

  // Deceptive — ASCII homoglyph (J4, weight 0.2 → low: meaningful in combination)
  {
    input: "https://g00gle.com",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ascii_homoglyph"],
    forbidReasons: ["mixed_script"],
    notes: "J4 zeros-for-o (reads as google) — same-script, no mixed_script",
  },
  {
    input: "https://paypa1.com",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ascii_homoglyph"],
    notes: "J4 one-for-l (reads as paypal)",
  },

  // Deceptive — IPv6 obfuscation (J5, weight 0.4 → medium)
  {
    input: "https://[::ffff:127.0.0.1]/",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "J5 IPv4-mapped IPv6 — SSRF masquerade for 127.0.0.1",
  },
  {
    input: "https://[2001:0db8::1]/",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "J5 non-canonical IPv6 (leading zeros)",
  },

  // Deceptive — file-extension TLD (J6, weight 0.4 → medium)
  {
    input: "https://invoice.zip/",
    label: "deceptive",
    expectReasons: ["file_extension_tld"],
    forbidReasons: ["risky_tld"],
    notes: "J6 bare filename masquerade — owns .zip (not risky_tld)",
  },
  {
    input: "https://setup.mov",
    label: "deceptive",
    expectReasons: ["file_extension_tld"],
    notes: "J6 .mov filename masquerade",
  },

  // Deceptive — brand in path (J7, weight 0.2 → low)
  {
    input: "https://evil.com/paypal.com/login",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["brand_in_path"],
    notes: "J7 brand domain planted in the path of evil.com",
  },
  {
    input: "https://phish.io/google/signin",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["brand_in_path"],
    notes: "J7 brand keyword + credential-flow path",
  },

  // Informational — IDNA mapping ambiguity (J9, weight 0): annotate, stay benign
  {
    input: "https://wordpreß.com",
    label: "info",
    expectReasons: ["idna_mapping_ambiguity"],
    forbidReasons: ["mixed_script"],
    notes: "J9 ß: IDNA2003 → wordpress.com vs UTS-46 punycode (Epic G escalates)",
  },
  {
    input: "https://ｇｏｏｇｌｅ.com",
    label: "info",
    expectReasons: ["idna_mapping_ambiguity"],
    notes: "J9 Group B: fullwidth Latin folds to ASCII google.com",
  },

  // Invalid — structurally ambiguous but unresolvable: carries a reason, not bare parse_error
  {
    input: "//evil.com",
    label: "invalid",
    expectReasons: ["ambiguous_authority"],
    notes: "J1 protocol_relative — invalid yet explained",
  },
  {
    input: "http://127.0.0.1:11211:80/",
    label: "invalid",
    expectReasons: ["ambiguous_authority"],
    notes: "J1 multiple_port — invalid yet explained",
  },
  {
    input: "http://google。com",
    label: "invalid",
    expectReasons: ["separator_lookalike"],
    notes: "J2 ideographic full stop — parser-discarded, still explained",
  },
  {
    input: "http://127.0.0.1 foo.google.com/",
    label: "invalid",
    expectReasons: ["control_char"],
    notes: "J3 whitespace-in-host — getaddrinfo strips the trailing rubbish",
  },

  // Benign (SC-2): the J detectors must NOT over-flag these
  { input: "https://[::1]:8080/", label: "benign", forbidReasons: ["ip_obfuscation"], notes: "J5: canonical IPv6 + port" },
  { input: "https://[2001:db8::1]/", label: "benign", forbidReasons: ["ip_obfuscation"], notes: "J5: canonical IPv6" },
  { input: "https://s3.amazonaws.com/my-bucket/key", label: "benign", forbidReasons: ["ascii_homoglyph"], notes: "J4: legit digit label (s3)" },
  { input: "https://web3.example.com/", label: "benign", forbidReasons: ["ascii_homoglyph"], notes: "J4: legit digit label (web3)" },
  { input: "https://bet365.com/", label: "benign", forbidReasons: ["ascii_homoglyph"], notes: "J4: non-homoglyph digits (3,6)" },
  { input: "https://github.com/anthropics/repo/archive/main.zip", label: "benign", forbidReasons: ["file_extension_tld"], notes: "J6: .zip in the path is a real file, not the TLD" },
  { input: "https://cdn.assets.acme.zip/", label: "benign", forbidReasons: ["file_extension_tld"], notes: "J6: deep-subdomain .zip reads as a site" },
  { input: "https://paypal.com/login", label: "benign", forbidReasons: ["brand_in_path"], notes: "J7: brand's own site" },
  { input: "https://medium.com/paypal-vs-stripe", label: "benign", forbidReasons: ["brand_in_path"], notes: "J7: brand word in prose, not a token" },
  { input: "https://github.com/paypal/repo", label: "benign", forbidReasons: ["brand_in_path"], notes: "J7: bare brand path, no credential context" },
  { input: "https://example.com:8443/a/b?x=1#frag", label: "benign", forbidReasons: ["ambiguous_authority"], notes: "J1: legit explicit port" },
  { input: "https://example.com//foo//bar", label: "benign", forbidReasons: ["ambiguous_authority"], notes: "J1: accidental double slashes in path" },
  { input: "https://sub.domain.example.co.uk/a/b/c/d/e", label: "benign", forbidReasons: ["embedded_domain_in_subdomain"], notes: "legit deep path + multi-level suffix" },

  // Informational — legitimate IDNs with deviation chars (ß / final sigma ς) stay benign
  { input: "https://straße.de/", label: "info", expectReasons: ["idna_mapping_ambiguity"], forbidReasons: ["mixed_script"], notes: "J9: legit German ß IDN — info only, must not flag" },
  { input: "https://ολυμπιακός.gr/", label: "info", expectReasons: ["idna_mapping_ambiguity"], forbidReasons: ["mixed_script"], notes: "J9: legit Greek IDN with final sigma ς" },

  // ── Imported IDN / PSL / host test vectors (E6) ─────────────────────────
  ...VECTORS,
];
