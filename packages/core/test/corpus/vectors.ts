import type { InspectOptions } from "../../src/index.js";
import type { CorpusRow } from "./corpus.js";

/**
 * IDN handling defaults to `"block"` (a non-ASCII registrable domain emits the
 * scoring `idn_host` reason). These reference vectors test the *deception*
 * analysis of legitimate IDNs — orthogonal to the policy block — so they run
 * with `idnPolicy: "allow"` to isolate it. The default-block behavior is covered
 * by the dedicated idn-policy test.
 */
const ALLOW_IDN: InspectOptions = { idnPolicy: "allow" };

// Authority control chars for the paper vectors (E7), built from codepoints so
// the byte sequence is unambiguous in source (matches the corpus convention).
const TAB = String.fromCodePoint(0x09);
const CR = String.fromCodePoint(0x0d);
const LF = String.fromCodePoint(0x0a);

/**
 * E6 — shared IDN / PSL / host test vectors imported from the canonical sources
 * the sibling repos (punycoder, pslr, rurl) maintain. All are reference data
 * with permissive terms. Each row is mapped to linklint's expected label /
 * severity / reasons and verified against `inspect()`.
 *
 * Spread into the main CORPUS, so both the conformance test (D1) and the
 * precision/recall harness (D2) cover them.
 *
 * Sources:
 *  - RFC 3492 (Punycode) — multilingual round-trip example labels.
 *  - Unicode UTS#46 IdnaTestV2.txt — normalization edge cases (eszett, final
 *    sigma, ACE round-trip, trailing root dot, label length).
 *  - publicsuffix.org test data — wildcard (*.ck), exception (!www.ck),
 *    multi-level (kobe.jp), private (blogspot.com), unknown TLD.
 *  - rurl/punycoder verified host edge cases — octal IPv4, out-of-range IPv4,
 *    FQDN root dot, empty labels.
 */
export const VECTORS: CorpusRow[] = [
  // ── Benign multilingual IDNs (RFC 3492) — must stay severity:info ──────────
  // Single-script U-labels + a TLD: any IDN trips normalization_delta only.
  {
    input: "https://мойдомен.рф",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script", "punycode_malformed"],
    notes: "Russian IDN + Cyrillic ccTLD (.рф)",
    source: "RFC 3492 / IANA IDN ccTLD",
  },
  {
    input: "https://例え.テスト",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "Japanese IDN + IDN TLD (.テスト)",
    source: "RFC 3492",
  },
  {
    input: "https://例子.中国",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "Chinese IDN + IDN ccTLD (.中国)",
    source: "RFC 3492",
  },
  {
    input: "https://나라.한국",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "Korean IDN + IDN ccTLD (.한국)",
    source: "RFC 3492",
  },
  {
    input: "https://उदाहरण.भारत",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "Hindi (Devanagari) IDN + IDN ccTLD (.भारत)",
    source: "RFC 3492",
  },
  {
    input: "https://مثال.إختبار",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script", "bidi_override"],
    notes: "Arabic (RTL) IDN — RTL letters must NOT trip bidi_override",
    source: "RFC 3492",
  },
  {
    input: "https://דוגמה.com",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script", "bidi_override"],
    notes: "Hebrew (RTL) IDN + ASCII TLD",
    source: "RFC 3492",
  },

  // ── UTS#46 IdnaTestV2 — normalization edge cases (must stay benign/info) ───
  {
    input: "https://faß.de",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script", "punycode_malformed"],
    notes: "eszett (ß) stays ß under non-transitional processing",
    source: "UTS#46 IdnaTestV2",
  },
  {
    input: "https://xn--fa-hia.de",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["punycode_malformed"],
    notes: "ACE form of faß.de — valid, must NOT be punycode_malformed",
    source: "UTS#46 IdnaTestV2",
  },
  {
    input: "https://straße.de",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "eszett mid-label",
    source: "UTS#46 IdnaTestV2",
  },
  {
    input: "https://Σίσυφος.gr",
    label: "info",
    options: ALLOW_IDN,
    expectReasons: ["normalization_delta"],
    forbidReasons: ["mixed_script"],
    notes: "Greek with final sigma — single-script, benign",
    source: "UTS#46 IdnaTestV2",
  },
  {
    input: `https://${"a".repeat(64)}.com`,
    label: "benign",
    // Both halves of §1.1's fourth rule in one pin: the score does NOT move
    // (over-long is not deception — §1.1's worked exclusion, and the reason
    // LINK-ygglwkuy was reverted), AND the fact is announced at weight 0 rather
    // than the caller being told there was nothing to say.
    expectReasons: ["host_length_unresolvable"],
    forbidReasons: ["mixed_script", "invisible_char"],
    notes: "over-long (64ch) label — not a deception finding; reported at weight 0, score stays 0.00",
    source: "UTS#46 IdnaTestV2 (DNS length)",
  },
  {
    input: "https://example.com./",
    label: "benign",
    // V7 (LINK-fboctpse). Same shape as the row above: the FQDN form resolves
    // identically and every parser reads it the same way, so it is NOT deception
    // and the score stays 0.00 — but a consumer allow-listing host STRINGS is
    // bypassed by the single trailing character (the Smokescreen bypass), which
    // is worth saying out loud. ambiguous_authority is forbidden on purpose: it
    // was the proposed home and was rejected because parsers do not disagree here.
    expectReasons: ["fqdn_root_label"],
    forbidReasons: ["ambiguous_authority", "separator_lookalike", "normalization_delta"],
    notes: "trailing root dot — valid FQDN form, reported at weight 0, score stays 0.00",
    source: "Smokescreen SSRF allow-list bypass (RFC 1034 §3.1)",
  },
  {
    // V9 (LINK-bitralnj). U+2028 LINE SEPARATOR in the path. It is category Zl,
    // not Cc/Cf, which is exactly why the \p{Cc}\p{Cf} class missed it while
    // catching U+200B and the Tags block. It is a line terminator in JavaScript
    // source, so a URL carrying one breaks in half wherever it is interpolated.
    input: "https://example.com/a\u2028b",
    label: "deceptive",
    expectReasons: ["invisible_char"],
    notes: "U+2028 LINE SEPARATOR in path — Zl, not Cc/Cf",
    source: "ECMA-262 line terminators / corpus verify list V9",
  },
  {
    input: "https://example.com/?a=\u2029",
    label: "deceptive",
    expectReasons: ["invisible_char"],
    notes: "U+2029 PARAGRAPH SEPARATOR in query — Zp, not Cc/Cf",
    source: "ECMA-262 line terminators / corpus verify list V9",
  },

  // ── T2.3 benign guard (LINK-ibwuayzo) — real multilingual URLs whose code
  // points ARE truncation-reachable but are NOT sandwiched between ASCII
  // alphanumerics. These are the false-positive class that killed the naive
  // "flag every truncation-reachable code point" rule: 有 上 下 名 載 all narrow
  // to a dangerous byte, and all of them appear in ordinary CJK URLs. If a future
  // weight or scope change makes low_byte_truncation fire here, that is the CJK
  // regression, not a win. See LINK-tyjxigyc before widening.
  {
    input: "https://example.jp/data\u4E0B\u8F09.zip",
    label: "benign",
    forbidReasons: ["low_byte_truncation"],
    notes: "下載 ('download'): 下 is truncation-reachable but its neighbour is CJK, not ASCII",
    source: "T2.3 realistic-URL measurement",
  },
  {
    input: "https://example.cn/\u4E0B\u8F09/index.html",
    label: "benign",
    forbidReasons: ["low_byte_truncation"],
    notes: "pure-CJK path segment — no ASCII sandwich",
    source: "T2.3 realistic-URL measurement",
  },
  {
    input: "https://example.cn/file\u540D.pdf",
    label: "benign",
    forbidReasons: ["low_byte_truncation"],
    notes: "名 (U+540D -> CR) preceded by ASCII but followed by '.', not an alphanumeric",
    source: "T2.3 realistic-URL measurement",
  },
  {
    input: "https://example.cn/\u4E0A\u4F20/img001.jpg",
    label: "benign",
    forbidReasons: ["low_byte_truncation"],
    notes: "上传 ('upload'): 上 is truncation-reachable, neighbours are '/' and CJK",
    source: "T2.3 realistic-URL measurement",
  },
  {
    input: "https://example.jp/PDF\u7248\u30C0\u30A6\u30F3\u30ED\u30FC\u30C9.pdf",
    label: "benign",
    forbidReasons: ["low_byte_truncation"],
    notes: "ASCII 'PDF' abutting kanji — the kanji's other neighbour is katakana",
    source: "T2.3 realistic-URL measurement",
  },

  // ── PSL vectors — wildcard / exception / multi-level (must stay benign) ────
  {
    input: "https://foo.ck/",
    label: "benign",
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "*.ck wildcard: foo.ck is itself a public suffix (no registrable domain)",
    source: "publicsuffix.org test data",
  },
  {
    input: "https://a.foo.ck/",
    label: "benign",
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "*.ck wildcard: registrable domain is a.foo.ck",
    source: "publicsuffix.org test data",
  },
  {
    input: "https://www.ck/",
    label: "benign",
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "!www.ck exception: www.ck IS a registrable domain",
    source: "publicsuffix.org test data",
  },
  {
    input: "https://city.kobe.jp/",
    label: "benign",
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "!city.kobe.jp exception under the *.kobe.jp wildcard",
    source: "publicsuffix.org test data",
  },
  {
    input: "https://foo.blogspot.com/",
    label: "benign",
    forbidReasons: ["embedded_domain_in_subdomain"],
    notes: "blogspot.com is a private suffix; ICANN-only rules keep it registrable, no embedded flag",
    source: "publicsuffix.org test data",
  },
  {
    input: "https://example.unknowntld/",
    label: "benign",
    notes: "unknown TLD — parses, no registrable domain surprise",
    source: "publicsuffix.org test data",
  },

  // ── Host edge cases (verified) ────────────────────────────────────────────
  {
    input: "01.2.3.4",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "octal IPv4 (leading zero on first octet)",
    source: "rurl verified host edge cases",
  },
  {
    input: "127.000.000.001",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    notes: "octal/zero-padded IPv4 form of 127.0.0.1",
    source: "rurl verified host edge cases",
  },
  {
    input: "999.1.1.1",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation", "ip_reserved", "ip_loopback"],
    notes:
      "out-of-range octet → no valid canonical IP, so NOT ip_obfuscation; a browser " +
      "rejects it but a fetcher resolves it as a host (ambiguous_numeric_host, P3)",
    source: "rurl verified host edge cases",
  },
  {
    input: "https://example.com.",
    label: "benign",
    notes: "FQDN trailing root dot → benign",
    source: "rurl verified host edge cases",
  },
  {
    input: "https://example.com..",
    label: "invalid",
    notes: "double trailing dot → empty label → unparseable",
    source: "rurl verified host edge cases",
  },
  {
    input: "https://a..b.com",
    label: "invalid",
    notes: "empty interior label → unparseable",
    source: "rurl verified host edge cases",
  },
  {
    input: "https://✓.com",
    label: "invalid",
    notes: "non-letter symbol host (U+2713) → not a valid reg-name",
    source: "rurl verified host edge cases",
  },

  // ── P3 (LINK-slcjsjcs): ambiguous_numeric_host ────────────────────────────
  // Malformed-IPv4-shaped hosts WHATWG rejects (last label numeric/hex/octal,
  // strict IPv4 parse fails). All score at medium; NEVER ip_obfuscation (no valid
  // canonical IP). Split by sub-shape for documentation; the harness only asserts
  // reasons + severity band.
  //
  // pure-IP-attempt: every label numeric/hex/octal.
  {
    input: "http://256.0.0.1/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation", "ip_reserved"],
    notes: "octet overflow (256 > 255) → no canonical IP; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://256.256.256.1/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "every octet overflows; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://0x100.2.3.4/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "hex octet 0x100 = 256 > 255 → overflow; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://1.2.3.4.5/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "> 4 parts; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://0x100000000/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "dotless hex > 2^32-1 → overflow; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://6442450945/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "dotless decimal > 2^32-1 (2^32 + 1) → overflow; pure-IP-attempt",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  // name-with-numeric-tail: ≥1 non-numeric label + numeric/hex terminal label.
  {
    input: "http://foo.1.2.3.4/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "non-numeric leading label but numeric tail → WHATWG IPv4 path; name-with-numeric-tail",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://foo.09/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "numeric terminal label on a name; name-with-numeric-tail",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://foo.0x4/",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "hex terminal label on a name; name-with-numeric-tail",
    source: "P3 / WHATWG IPv4 'ends in a number' rule",
  },
  {
    input: "http://foo.09./",
    label: "deceptive",
    expectReasons: ["ambiguous_numeric_host"],
    forbidReasons: ["ip_obfuscation"],
    notes: "trailing root dot normalized → behaves like foo.09; name-with-numeric-tail",
    source: "P3 / trailing-dot normalization",
  },
  // Consistency fix: 1.2.3.08 fired ip_obfuscation; the trailing-dot form now
  // does too (was silently missed). This is a real (obfuscated) IP, NOT
  // ambiguous_numeric_host — the strict parse succeeds (canonical 1.2.3.8).
  {
    input: "http://1.2.3.08./",
    label: "deceptive",
    expectReasons: ["ip_obfuscation"],
    forbidReasons: ["ambiguous_numeric_host"],
    notes: "trailing-dot obfuscated IP now recognized like 1.2.3.08 (recognizer normalizes root dot)",
    source: "P3 / trailing-dot normalization",
  },
  // Precision guards: numeric-adjacent hosts that must NOT trip the detector.
  {
    input: "https://3.pool.ntp.org/",
    label: "benign",
    forbidReasons: ["ambiguous_numeric_host", "ip_obfuscation"],
    notes: "numeric leading label but non-numeric tail (org) → not the IPv4 path",
    source: "P3 precision guard",
  },
  {
    input: "http://8.8.8.8/",
    label: "benign",
    forbidReasons: ["ambiguous_numeric_host", "ip_obfuscation"],
    notes: "valid canonical public dotted-quad → not ambiguous, not obfuscated",
    source: "P3 precision guard",
  },
  {
    input: "http://192.168.1.1/",
    label: "deceptive",
    minSeverity: "low",
    expectReasons: ["ip_private"],
    forbidReasons: ["ambiguous_numeric_host", "ip_obfuscation"],
    notes: "valid canonical private IP → ip_private only, never ambiguous_numeric_host",
    source: "P3 precision guard / no-regression",
  },

  // ── E7 (LINK-krzcupbk): adversarial URL-confusion paper vectors ────────────
  // Byte-verified vectors from two academic papers, transcribed into rurl's
  // committed external-url-vectors.csv (BSD-3-Clause feed) and mapped here to
  // linklint-NATIVE verdicts (linklint judges DECEPTION, not spec-conformance —
  // so these are NOT rurl's `diverges` verdicts). These lock in the measured
  // Epic-P finding: linklint already catches the dangerous host-swap / evasion
  // rows, mostly at CRITICAL, via shape detection.
  //
  //   Sources:
  //   - Reynolds/Bates/Bailey, "Equivocal URLs", ESORICS '22 (Best Paper),
  //     Table 3 U1–U8 + §6.2 GSB/VirusTotal misdirection vectors.
  //   - Ajmani/Koishybayev/Kapravelos, "yoU aRe a Liar", SecWeb '22, §V
  //     categories + §VI PoCs. Byte-verified vs wspr-ncsu/urlparsing-framework.
  //   (eq-U1 NUL and eq-U7 raw-octet vectors are non-runnable placeholders in the
  //   source and are intentionally omitted.)

  // yoU-aRe-a-Liar §V/§VI — backslash / control-char / slash host confusion.
  {
    input: "http://google.com:80\\@yahoo.com",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["ambiguous_authority", "userinfo_present"],
    notes: "yal-001 §V.1 backslash-before-@ host swap (CVE-2020-26291); real host yahoo.com",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.1 (via rurl external-url-vectors.csv)",
  },
  {
    input: `https://user:pass@xdavidhu.me${TAB}est.corp.google.com`,
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["control_char", "ambiguous_authority"],
    notes: "yal-002 §V.3 literal TAB in authority — WHATWG strips, others disagree",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.3 (via rurl external-url-vectors.csv)",
  },
  {
    input: `http://127.0.0.${CR}${LF}1:6379?SET${CR}${LF}test${CR}${LF}failure12:80`,
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["control_char", "ip_loopback"],
    notes: "yal-003 §V.3 CRLF-in-host redis SSRF; WHATWG resolves to 127.0.0.1",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.3 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https:/\\/\\/\\github.com/foo/bar",
    label: "invalid",
    expectReasons: ["ambiguous_authority"],
    notes: "yal-004 §V.4 mixed //\\ before host — ambiguous authority, unparseable",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.4 (via rurl external-url-vectors.csv)",
  },
  {
    input: "http://ヒ:キ@ヒ.abc.ニ/ヒ",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["userinfo_present"],
    notes: "yal-005 §V.7 non-ASCII host + userinfo spoof (katakana)",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.7 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https:///evil.com",
    label: "invalid",
    expectReasons: ["ambiguous_authority"],
    notes: "yal-006 §VI.B empty-authority slash confusion — RFC-empty-host SSRF-filter bypass PoC",
    source: "yoU-aRe-a-Liar SecWeb'22 §VI.B (via rurl external-url-vectors.csv)",
  },
  {
    input: "http://example.com:80\\@localhost:8080/secret.txt",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["ambiguous_authority", "userinfo_present"],
    notes: "yal-007 §VI.A allow-list-bypass PoC (validate example.com, fetch localhost)",
    source: "yoU-aRe-a-Liar SecWeb'22 §VI.A (via rurl external-url-vectors.csv)",
  },
  {
    input: "foo://///////bar.com/",
    label: "invalid",
    expectReasons: ["ambiguous_authority"],
    notes: "yal-008 §V.5 many-slashes non-special scheme — ambiguous authority",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.5 (via rurl external-url-vectors.csv)",
  },
  {
    input: "www.php.net:80/index.php?test=1",
    label: "benign",
    forbidReasons: ["ambiguous_authority", "userinfo_present"],
    notes:
      "yal-009 §V.2 schemeless host:port — documented Epic-P low-value MISS: no attacker host, " +
      "linklint infers http and reads www.php.net as host (benign)",
    source: "yoU-aRe-a-Liar SecWeb'22 §V.2 (via rurl external-url-vectors.csv)",
  },

  // Equivocal URLs, Table 3 (U2–U8) + §6.2 GSB evasion.
  {
    input: "https://n.pr\\@e.gg",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["ambiguous_authority", "userinfo_present"],
    notes: "eq-U2 Pitfall 2 backslash correction; browsers→n.pr, RFC→e.gg",
    source: "Equivocal URLs ESORICS'22 Table 3 U2 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://n.pr][e.gg",
    label: "invalid",
    notes: "eq-U3 Pitfall 4 balanced-but-unmatched brackets ][ in host — unparseable",
    source: "Equivocal URLs ESORICS'22 Table 3 U3 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://n.pr#@e.gg",
    label: "deceptive",
    minSeverity: "high",
    expectReasons: ["ambiguous_authority"],
    notes: "eq-U4 Pitfall 7 extra delimiter (# then @) — # opens fragment, host n.pr",
    source: "Equivocal URLs ESORICS'22 Table 3 U4 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://n.pr%2ee.gg",
    label: "deceptive",
    expectReasons: ["encoding_obfuscation"],
    notes: "eq-U5 Pitfall 3 overeager %2e decode → n.pr.e.gg; encoded '.' in host",
    source: "Equivocal URLs ESORICS'22 Table 3 U5 (via rurl external-url-vectors.csv)",
  },
  {
    input: `https://n.pr${LF}e.gg`,
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["control_char"],
    notes: "eq-U6 Pitfall 6 LF (0x0A) in host — WHATWG strips, linklint flags the control char",
    source: "Equivocal URLs ESORICS'22 Table 3 U6 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://n.prİ@e.gg",
    label: "deceptive",
    expectReasons: ["userinfo_present"],
    notes: "eq-U8 Pitfall 5 dotted-capital İ (U+0130) then @ — userinfo spoof, real host e.gg",
    source: "Equivocal URLs ESORICS'22 Table 3 U8 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://malware.testing.google.test/testing/malware/*",
    label: "benign",
    forbidReasons: ["userinfo_present", "ambiguous_authority", "embedded_domain_in_subdomain"],
    notes:
      "eq-gsb §6.2 GSB always-flagged baseline — NOT lexically deceptive; linklint is a lexical " +
      "deception detector, not a reputation/blocklist service (benign by design)",
    source: "Equivocal URLs ESORICS'22 §6.2 (via rurl external-url-vectors.csv)",
  },
  {
    input: "http://letsencrypt.org%2F@malware.testing.google.test/testing/malware/*",
    label: "deceptive",
    expectReasons: ["userinfo_present"],
    notes:
      "eq-pe1 §6.2 GSB API/web evasion via %2F over-decode — real host is the google.test malware " +
      "host; linklint flags the userinfo spoof GSB missed",
    source: "Equivocal URLs ESORICS'22 §6.2 (via rurl external-url-vectors.csv)",
  },
  {
    input: "http://letsencrypt.org%5C@malware.testing.google.test/testing/malware/*",
    label: "deceptive",
    expectReasons: ["userinfo_present"],
    notes: "eq-pe2 §6.2 GSB API evasion via %5C backslash-correction — userinfo spoof",
    source: "Equivocal URLs ESORICS'22 §6.2 (via rurl external-url-vectors.csv)",
  },
  {
    input: "https://malware.testing.google.test\\testing\\malware\\*@letsencrypt.org",
    label: "deceptive",
    minSeverity: "critical",
    expectReasons: ["ambiguous_authority", "userinfo_present"],
    notes: "eq-bs §6.2 GSB web-interface evasion via literal backslashes — host equivocation",
    source: "Equivocal URLs ESORICS'22 §6.2 (via rurl external-url-vectors.csv)",
  },

  // ── E8 (LINK-krzcupbk): PSL-harms multi-tenant eTLD benign set ─────────────
  // McQuistin et al., "Privacy Harms of the PSL" (IMC '23), Table 2. These legit
  // multi-tenant hosts must stay BENIGN in the full inspect() pipeline — a stale
  // PSL or an over-eager embedded-domain/brand heuristic must not manufacture a
  // false deception signal. (The PSL FRESHNESS gate — asserting the correct
  // registrable boundary against the bundled list — lives in freshness-corpus.
  // test.ts, P2; these rows guard the deception layer, not the boundary.)
  ...(
    [
      "https://myshop.myshopify.com/",
      "https://docs.readthedocs.io/",
      "https://myapp.netlify.app/",
      "https://site.web.app/",
      "https://portfolio.carrd.co/",
      "https://bucket.nyc3.digitaloceanspaces.com/",
      "https://svc.uc.r.appspot.com/",
    ] as const
  ).map(
    (input): CorpusRow => ({
      input,
      label: "benign",
      forbidReasons: ["embedded_domain_in_subdomain", "ambiguous_authority"],
      notes: "IMC'23 Table-2 multi-tenant eTLD — legit tenant host, no false deception signal",
      source: "PSL-harms IMC'23 Table 2 (via pslr / P2 freshness corpus)",
    }),
  ),

  // ── LINK-lippdgpn tripwire: digit-bearing tenants that must NOT escalate ───
  // The hyphen/label token tier joins folded tokens against the brand LABEL set,
  // which is exactly the widening that could start calling ordinary personal
  // tenants brand impersonation. These two fold to NOTHING on the watchlist
  // (`pete1` -> `petel`, `haru01` -> `haruol`), so they must stay pinned at the
  // list-free `ascii_homoglyph` floor — 0.20/low, no `brand_homoglyph`.
  //
  // The IMC'23 rows above cannot guard this: they contain no digits at all and
  // therefore cannot fire either way.
  ...(["https://pete1.github.io/", "https://haru01.github.io/"] as const).map(
    (input): CorpusRow => ({
      input,
      label: "deceptive",
      minSeverity: "low",
      expectReasons: ["ascii_homoglyph"],
      forbidReasons: ["brand_homoglyph", "embedded_domain_in_subdomain"],
      notes:
        "LINK-lippdgpn tripwire — benign digit-bearing multi-tenant host; the label/token " +
        "tier must not escalate it past the 0.20 ascii_homoglyph floor",
      source: "LINK-lippdgpn (fold-gated token join)",
    }),
  ),
];
