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
    forbidReasons: ["mixed_script", "invisible_char"],
    notes: "over-long (64ch) label — linklint is a lexical inspector, not a DNS validator; tolerated",
    source: "UTS#46 IdnaTestV2 (DNS length)",
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
];
