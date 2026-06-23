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
    label: "benign",
    forbidReasons: ["ip_obfuscation"],
    notes: "out-of-range octet → treated as a host, not an IP",
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
];
