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
// Cyrillic homoglyphs for E3 single-script whole-label homograph fixtures.
const cyr = (...cps: number[]): string => String.fromCodePoint(...cps);
// сһаѕе.com — all-Cyrillic look-alike of chase.com (no script mixing).
const CYR_CHASE = cyr(0x0441, 0x04bb, 0x0430, 0x0455, 0x0435) + ".com";
// ехреԁіа.com — all-Cyrillic look-alike of expedia.com.
const CYR_EXPEDIA = cyr(0x0435, 0x0445, 0x0440, 0x0435, 0x0501, 0x0456, 0x0430) + ".com";

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
    expectReasons: ["ip_obfuscation", "ip_loopback"],
    notes: "decimal-encoded 127.0.0.1 — V1b: decodes to loopback, so also ip_loopback",
  },
  {
    input: "http://0x7f.0.0.1/",
    label: "deceptive",
    expectReasons: ["ip_obfuscation", "ip_loopback"],
    notes: "hex-encoded IP (127.0.0.1) — V1b: decodes to loopback, so also ip_loopback",
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
    input: "file:/etc/passwd",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["dangerous_scheme"],
    notes: "hostless local file: (single slash) — local-file-read; must not slip to invalid",
  },
  {
    input: "file:///etc/passwd",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["dangerous_scheme"],
    notes: "hostless local file: (empty authority) — same local-file-read class",
  },
  {
    input: "https://example.com/%2e%2e%2f%2e%2e%2fadmin",
    label: "deceptive",
    expectReasons: ["encoding_obfuscation"],
    notes: "encoded traversal",
  },
  {
    input: "https://example.com/%C0%AFadmin",
    label: "deceptive",
    expectReasons: ["encoding_obfuscation"],
    notes: "overlong UTF-8: C0 AF folds to '/' under permissive decoding — hides a path separator",
  },
  {
    input: "https://example.com/%25252e%25252e%25252fadmin",
    label: "deceptive",
    expectReasons: ["encoding_obfuscation"],
    notes: "triple-encoded traversal — '..' and '/' hidden behind three percent-encoding levels",
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
  // V1b reclassification: canonical literal-IP internal links. NOT ip_obfuscation
  // (that invariant holds), but the V1a range classifier now emits a low-weight
  // bucket signal (a public-facing URL has no business naming an internal target),
  // so these score low and read as deceptive at minSeverity low — see worklog.
  { input: "192.168.1.1", label: "deceptive", minSeverity: "low", expectReasons: ["ip_private"], forbidReasons: ["ip_obfuscation"], notes: "canonical RFC 1918 internal link — low-weight ip_private signal, not obfuscation" },
  { input: "http://127.0.0.1:3000/", label: "deceptive", minSeverity: "low", expectReasons: ["ip_loopback"], forbidReasons: ["ip_obfuscation"], notes: "canonical loopback internal link — low-weight ip_loopback signal, not obfuscation" },
  { input: "example.com", label: "benign", notes: "bare host, missing scheme" },
  { input: "https://example.com/?redirect=https%3A%2F%2Fexample.com%2Fp", label: "benign", forbidReasons: ["encoding_obfuscation", "open_redirect_param"], notes: "legitimate encoded SAME-host redirect value (A→A): guards encoding_obfuscation and open_redirect_param. Cross-host (A→B) deceptive case is an I4 corpus row." },

  // ── Informational-only (SC-1a): annotate, weight 0, benign ──────────────
  { input: "https://xn--bcher-kva.de/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script", "punycode_malformed"], notes: "bücher.de ACE form" },
  { input: "https://XN--CAF-DMA.com/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["punycode_malformed"], notes: "E5 guard: uppercase ACE round-trips to café — NOT malformed" },
  { input: "https://müller.de/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script"], notes: "legitimate German IDN" },
  { input: "https://пример.com", label: "info", expectReasons: ["confusable_char", "normalization_delta"], forbidReasons: ["mixed_script", "homograph_skeleton_collision"], notes: "single-script Cyrillic label + ASCII TLD — E3 guard: skeleton is not a brand" },
  { input: "https://日本語.jp/", label: "info", expectReasons: ["normalization_delta"], forbidReasons: ["mixed_script"], notes: "Japanese IDN" },
  { input: `https://example.com/p${CYR_A}y`, label: "info", expectReasons: ["confusable_in_path"], notes: "path-embedded confusable" },

  // ── Invalid (SC-2a): not benign ─────────────────────────────────────────
  { input: "ht!tp://%%%not a url", label: "invalid" },
  { input: "", label: "invalid" },
  { input: "   ", label: "invalid" },
  { input: "http://", label: "invalid" },
  { input: "http://exa mple.com", label: "invalid", notes: "space in host" },
  { input: "@@@@@", label: "invalid" },
  { input: "file:// /etc/passwd", label: "invalid", notes: "regression: hostless file: special-case must not rescue a malformed (whitespace) authority" },

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
    expectReasons: ["ip_obfuscation", "ip_loopback"],
    notes: "J5 IPv4-mapped IPv6 — SSRF masquerade for 127.0.0.1; V1b classifies by embedded v4 → ip_loopback",
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
  { input: "https://[::1]:8080/", label: "deceptive", minSeverity: "low", expectReasons: ["ip_loopback"], forbidReasons: ["ip_obfuscation"], notes: "J5/V1b: canonical IPv6 loopback + port — low-weight ip_loopback signal, not obfuscation" },
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

  // ── Epic I: download / redirect / subdomain-depth detectors (I1–I3) ──────
  // Deceptive — suspicious executable extension (I1, weight 0.5 → medium)
  {
    input: "https://cdn.example.com/setup.exe",
    label: "deceptive",
    expectReasons: ["suspicious_extension"],
    notes: "I1 direct executable download (.exe)",
  },
  {
    input: "https://files.example.com/invoice.pdf.exe",
    label: "deceptive",
    expectReasons: ["suspicious_extension"],
    notes: "I1 double-extension lure — visible .pdf, real .exe",
  },

  // Deceptive — open-redirect parameter (I2, weight 0.4 → medium): the cross-host (A→B) case
  {
    input: "https://example.com/login?next=https://evil.com/phish",
    label: "deceptive",
    expectReasons: ["open_redirect_param"],
    notes: "I2 cross-host (A→B) redirect payload deferred from I2 — reads as example.com, lands on evil.com",
  },
  {
    input: "https://example.com/login?next=https%253A%252F%252Fevil.com%252Fphish",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["open_redirect_param", "encoding_obfuscation"],
    notes: "I2 double-encoded cross-host payload (stacks encoding_obfuscation → high)",
  },

  // Deceptive — excessive subdomain depth (I3, weight 0.15 → low alone)
  {
    input: "https://a.b.c.d.e.example.com/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["excessive_subdomain_depth"],
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "I3 deep subdomain alone (5 labels) — low weight, no embedded registrable-domain window",
  },
  {
    input: "https://a.b.c.d.paypal.com.evil-login.tk/",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["excessive_subdomain_depth"],
    notes: "I3 deep-subdomain phish — stacks embedded_domain_in_subdomain + risky_tld → high",
  },

  // Benign (SC-2): the I detectors must NOT over-flag these
  { input: "https://cdn.assets.eu-west-1.svc.example.com/", label: "benign", forbidReasons: ["excessive_subdomain_depth"], notes: "I3 guard: 4-label subdomain stays below the ≥5 threshold" },
  { input: "https://example.com/login?next=/dashboard", label: "benign", forbidReasons: ["open_redirect_param"], notes: "I2 guard: relative same-host redirect value" },
  { input: "https://app.example.com/?next=https://www.example.com/x", label: "benign", forbidReasons: ["open_redirect_param"], notes: "I2 guard: target is the same registrable domain (subdomain of example.com)" },
  { input: "https://files.example.com/report.pdf", label: "benign", forbidReasons: ["suspicious_extension"], notes: "I1 guard: .pdf is not an executable extension" },
  { input: "https://files.example.com/archive.zip", label: "benign", forbidReasons: ["suspicious_extension"], notes: "I1 guard: .zip archive is deliberately excluded from the dangerous set" },
  { input: "https://files.example.com/photo.png", label: "benign", forbidReasons: ["suspicious_extension"], notes: "I1 guard: image download is ordinary" },

  // ── Epic G: brand-proximity family (G2 homoglyph/lookalike, G3 combosquat, G4 bait) ──
  // Deceptive — brand_homoglyph (G2, weight 0.5): registrable domain folds via
  // ASCII digit look-alikes to EXACTLY a watchlist brand → stacks with the J4
  // ascii_homoglyph signal → high.
  {
    input: "https://paypa1.com",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["brand_homoglyph"],
    notes: "G2 one-for-l folds paypa1.com -> paypal.com (exact brand) — also J4 ascii_homoglyph",
  },
  {
    input: "https://g00gle.com",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["brand_homoglyph"],
    forbidReasons: ["mixed_script"],
    notes: "G2 zeros-for-o folds g00gle.com -> google.com (exact brand) — same-script",
  },
  {
    input: "https://revo1ut.com",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["brand_homoglyph"],
    notes: "G2 one-for-l folds revo1ut.com -> revolut.com (exact brand)",
  },

  // Deceptive — brand_lookalike (G2, weight 0.4 → medium): edit-distance / TLD-swap near-miss.
  {
    input: "https://gogole.com",
    label: "deceptive",
    expectReasons: ["brand_lookalike"],
    forbidReasons: ["brand_homoglyph"],
    notes: "G2 transposition typosquat of google.com (distance 1)",
  },
  {
    input: "https://microsoftt.com",
    label: "deceptive",
    expectReasons: ["brand_lookalike"],
    notes: "G2 doubled-letter typosquat of microsoft.com (distance 1)",
  },
  {
    input: "https://paypal.co",
    label: "deceptive",
    expectReasons: ["brand_lookalike"],
    notes: "G2 TLD-swap near-miss of paypal.com (.co for .com) — visible only on full registrable domain",
  },

  // Deceptive — brand_combosquat (G3, weight 0.4 → medium): brand keyword hyphen-glued to additive token.
  {
    input: "https://paypal-secure.com",
    label: "deceptive",
    expectReasons: ["brand_combosquat"],
    forbidReasons: ["brand_lookalike", "brand_homoglyph"],
    notes: "G3 combosquat — registrable label 'paypal-secure' (brand + additive token)",
  },
  {
    input: "https://login-paypal.com",
    label: "deceptive",
    expectReasons: ["brand_combosquat"],
    notes: "G3 combosquat — additive token glued before the brand keyword",
  },

  // Deceptive — brand_soundsquat (T2, weight 0.3 → medium): phonetic homophone of
  // a brand, INVISIBLE to the edit-distance / digit-fold siblings (these flag
  // nothing else, so soundsquat alone is the recall).
  {
    input: "https://netflicks.com",
    label: "deceptive",
    expectReasons: ["brand_soundsquat"],
    forbidReasons: ["brand_lookalike", "brand_homoglyph"],
    notes: "T2 soundsquat — netflicks sounds like netflix (ck->k, x->ks); below G2's edit-distance gate",
  },
  {
    input: "https://dropboks.com",
    label: "deceptive",
    expectReasons: ["brand_soundsquat"],
    forbidReasons: ["brand_lookalike", "brand_homoglyph"],
    notes: "T2 soundsquat — dropboks sounds like dropbox (x->ks); invisible to edit distance",
  },

  // Deceptive — brand_bitsquat (T3, weight 0.15 → LOW alone): a single-bit-flip
  // neighbor of a brand label (memory/transmission-error attack class). A bit
  // flip is by construction also edit-distance 1, so brand_lookalike STACKS and
  // lifts the aggregate — but brand_bitsquat alone is LOW, hence minSeverity low.
  // netfliz <- netflix: byte 'x'=0x78, flip bit 1 (XOR 0x02) -> 'z'=0x7a.
  {
    input: "https://netfliz.com",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["brand_bitsquat"],
    forbidReasons: ["brand_homoglyph", "brand_soundsquat"],
    notes: "T3 bitsquat — netfliz is netflix with byte 'x'=0x78 bit 1 flipped to 'z' (also brand_lookalike, distance 1)",
  },
  {
    input: "https://amazgn.com",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["brand_bitsquat"],
    forbidReasons: ["brand_homoglyph", "brand_soundsquat"],
    notes: "T3 bitsquat — amazgn is amazon with byte 'o'=0x6f bit 3 flipped to 'g'=0x67",
  },

  // Deceptive — bait_tokens (G4, weight 0.15 → LOW alone): set minSeverity low.
  {
    input: "https://secure-account-verify-login.com",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["bait_tokens"],
    notes: "G4 bait-stacked host (4 distinct bait tokens) — low weight alone, so minSeverity low",
  },

  // Deceptive — homograph_skeleton_collision (E3, weight 0.5 → medium): a
  // single-script, all-Cyrillic whole-label homograph whose UTS#39 skeleton
  // equals a watchlist brand. No script mixing, so mixed_script is silent —
  // this detector is the only thing that catches it. Mutually exclusive with
  // the ASCII-digit brand_homoglyph (which runs only on pure-ASCII hosts).
  {
    input: `https://${CYR_CHASE}`,
    label: "deceptive",
    expectReasons: ["homograph_skeleton_collision"],
    forbidReasons: ["mixed_script", "brand_homoglyph", "brand_lookalike"],
    notes: "E3 all-Cyrillic сһаѕе.com skeletonizes to chase.com (single-script whole-label homograph)",
  },
  {
    input: `https://${CYR_EXPEDIA}`,
    label: "deceptive",
    expectReasons: ["homograph_skeleton_collision"],
    forbidReasons: ["mixed_script", "brand_homoglyph"],
    notes: "E3 all-Cyrillic ехреԁіа.com skeletonizes to expedia.com",
  },

  // Benign (SC-2): the G family must NOT over-flag these.
  { input: "https://paypal.com", label: "benign", forbidReasons: ["brand_lookalike", "brand_homoglyph", "brand_combosquat", "homograph_skeleton_collision"], notes: "G2/G3/E3 guard: exact brand domain is the brand, never fires" },
  { input: "https://chase.com", label: "benign", forbidReasons: ["homograph_skeleton_collision", "brand_lookalike"], notes: "E3 guard: the real (ASCII) brand is guarded out before any skeleton collision" },
  { input: "https://google.com", label: "benign", forbidReasons: ["brand_lookalike", "brand_homoglyph"], notes: "G2 guard: exact brand domain" },
  { input: "https://microsoft.com", label: "benign", forbidReasons: ["brand_lookalike", "brand_homoglyph"], notes: "G2 guard: exact brand domain" },
  { input: "https://accounts.google.com", label: "benign", forbidReasons: ["brand_combosquat", "bait_tokens"], notes: "G3/G4 guard: legit brand subdomain, single bait token, registrable domain is the brand" },
  { input: "https://login.microsoftonline.com", label: "benign", forbidReasons: ["brand_combosquat", "bait_tokens", "brand_lookalike"], notes: "G3/G4 guard: legit MS login host — single bait token, no hyphen-combo" },
  { input: "https://amazonaws.com", label: "benign", forbidReasons: ["brand_combosquat", "brand_lookalike", "brand_soundsquat"], notes: "G3 guard: 'amazonaws' is a single concatenated token (no hyphen), not a combosquat" },
  { input: "https://example.com/account/login", label: "benign", forbidReasons: ["bait_tokens"], notes: "G4 guard: 2 path-only bait tokens stays UNDER the host>=2 / total>=3 threshold" },
  { input: "https://netflix.com", label: "benign", forbidReasons: ["brand_soundsquat", "brand_lookalike", "brand_bitsquat"], notes: "T2/T3 guard: exact brand domain is the brand, never a homophone or bit-flip of itself" },
  { input: "https://dropbox.com", label: "benign", forbidReasons: ["brand_soundsquat", "brand_lookalike"], notes: "T2 guard: exact brand domain" },
  { input: "https://ups.com", label: "benign", forbidReasons: ["brand_soundsquat", "brand_bitsquat"], notes: "T2/T3 short-label guard: 3-char brand label cannot soundsquat/bitsquat-collide" },
  { input: "https://amazon.com", label: "benign", forbidReasons: ["brand_bitsquat", "brand_lookalike"], notes: "T3 guard: exact brand domain is the brand, never a bit-flip of itself" },
  { input: "https://oetfliz.com", label: "benign", forbidReasons: ["brand_bitsquat"], notes: "T3 guard: a 2-bit-away label (n->o AND x->z off netflix) is NOT a single-bit neighbor" },

  // ── V1b: literal-IP range classifier coverage (5 buckets + precedence + v4-in-v6) ──
  // Each literal-IP host carries a scoring bucket signal (generic 0.2 → low,
  // cloud-metadata 0.5 → medium), so every fixture is deceptive. Grounded in
  // technique (RFC ranges / SSRF target shapes), no advisory IDs.

  // Private (RFC 1918) — v4 and v6 (fc00::/7 unique-local).
  {
    input: "http://10.1.2.3/admin",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_private"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b private bucket — 10/8 internal target",
  },
  {
    input: "http://172.16.5.5/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_private"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b private bucket — 172.16/12 internal target",
  },
  {
    input: "https://[fd12:3456:789a::1]/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_private"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b private bucket (IPv6) — fc00::/7 unique-local",
  },

  // Loopback — v4 (127/8) and v6 (::1) beyond the reclassified canonical rows.
  {
    input: "http://127.5.6.7/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_loopback"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b loopback bucket — 127/8 (not just 127.0.0.1)",
  },

  // Link-local — v4 (169.254/16, NOT the metadata /32) and v6 (fe80::/10).
  {
    input: "http://169.254.10.20/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_link_local"],
    forbidReasons: ["ip_obfuscation", "ip_cloud_metadata"],
    notes: "V1b link-local bucket — 169.254/16 generic (NOT the metadata endpoint)",
  },
  {
    input: "https://[fe80::abcd]/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_link_local"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b link-local bucket (IPv6) — fe80::/10",
  },

  // Cloud-metadata (most-specific bucket, deceptive-labeled) — v4 and v6 literals.
  {
    input: "http://169.254.169.254/latest/meta-data/",
    label: "deceptive",
    expectReasons: ["ip_cloud_metadata"],
    forbidReasons: ["ip_link_local", "ip_obfuscation"],
    notes: "V1b precedence — the metadata /32 wins over the 169.254/16 link-local range",
  },
  {
    input: "https://[fd00:ec2::254]/",
    label: "deceptive",
    expectReasons: ["ip_cloud_metadata"],
    forbidReasons: ["ip_private", "ip_obfuscation"],
    notes: "V1b cloud-metadata bucket (IPv6) — wins over the fc00::/7 unique-local range",
  },

  // Reserved / special-use — v4 (0/8, CGNAT, multicast) and v6 (unspecified, multicast).
  {
    input: "http://0.0.0.10/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_reserved"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b reserved bucket — 0/8 special-use",
  },
  {
    input: "http://100.64.1.1/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_reserved"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b reserved bucket — 100.64/10 CGNAT",
  },
  {
    input: "http://239.0.0.1/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_reserved"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b reserved bucket — 224/4 multicast",
  },
  {
    input: "https://[ff02::1]/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_reserved"],
    forbidReasons: ["ip_obfuscation"],
    notes: "V1b reserved bucket (IPv6) — ff00::/8 multicast",
  },

  // v4-in-v6 embeddings — classified by the EMBEDDED IPv4 (SSRF masquerade).
  {
    input: "https://[::ffff:169.254.169.254]/",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["ip_cloud_metadata", "ip_obfuscation"],
    notes: "V1b v4-in-v6 — embedded metadata endpoint classifies as ip_cloud_metadata (+ ip_obfuscation → high)",
  },

  // ── Imported IDN / PSL / host test vectors (E6) ─────────────────────────
  ...VECTORS,
];
