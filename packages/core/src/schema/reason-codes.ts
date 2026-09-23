import type { Layer } from "./types.js";

/**
 * Correlation families — the URL feature each reason code reads (LINK-tviundio).
 *
 * `Layer` answers *where in the pipeline* a code comes from. It does not answer
 * *what evidence the code rests on*, and those are different questions: one
 * Cyrillic code point in `apple.com` raises six lexical-layer codes off a single
 * character. Reading those six as six findings overstates the case, so the
 * registry names the feature instead of leaving a reader to infer independence
 * from the layer.
 *
 * The placement rule, the tie-break for a code that reads two features at once,
 * and the worked cases behind this partition are in `docs/reason-codes.md`
 * under "Correlation families". That section is the normative statement; the
 * one-line descriptions here are its index. Families cut ACROSS layers on
 * purpose — `url_scheme` holds a lexical detector, a resolution observation and
 * a policy verdict, because a triager who has seen one has seen the feature the
 * other two rest on.
 *
 * This metadata is registry-only. It is not a field on the serialized
 * `InspectResult`, so `SCHEMA_VERSION` does not move for it; a surface that
 * wants to group `reasons[]` reads it from the exported registry by code.
 */
export const REASON_FAMILIES = {
  character_identity:
    "Which characters the authority is actually spelled with, as against the letters a reader takes them for.",
  idn_form:
    "Whether the host is already in its normalized ASCII form, and whether that form is a well-formed encoding of a permitted name.",
  percent_escapes: "The percent-escape sequences in the URL string.",
  decoded_bytes:
    "What a downstream reader ends up with after decoding or narrowing a code point that is not rendered as itself.",
  authority_delimiters: "Where a parser decides the authority ends and the host begins.",
  host_label_arrangement: "How the labels left of the registrable domain are arranged.",
  address_literal: "The host is an address literal, and which range it lands in.",
  dns_name_status: "What the DNS would do with the name, independent of how it looks.",
  url_scheme: "Which scheme the request ends up speaking.",
  file_shape: "Whether the URL is dressed as a downloadable file.",
  query_payload: "What the path and query carry as a payload for whatever consumes them.",
  response_content: "What a fetched response's bytes turn out to be.",
  reputation_listing: "Whether the exact URL appears in a caller-owned mirror snapshot.",
  policy_tld: "The host's TLD, weighed against the caller's own lists.",
  policy_host: "The host's registrable domain, weighed against the caller's own lists.",
  policy_port: "The explicit port, weighed against the caller's own list.",
  parse_failure: "The input did not parse, so no other feature could be read.",
} as const;

/** Union of every declared correlation family. */
export type ReasonFamily = keyof typeof REASON_FAMILIES;

export interface ReasonCodeMeta {
  /** Inspection layer the code belongs to. v1 codes are all `lexical`. */
  layer: Layer;
  /**
   * Correlation family — the URL feature this code reads. Two codes sharing a
   * family are two readings of one feature rather than independent evidence.
   * See {@link REASON_FAMILIES}.
   */
  family: ReasonFamily;
  /** Whether the code contributes to the risk score. */
  scoring: boolean;
  /** Version-pinned weight in [0,1]. Always 0 for informational codes. */
  weight: number;
  /** One-line summary for docs and UI surfaces. */
  summary: string;
}

/**
 * Reason-code registry — the single source of truth for every code linklint can
 * emit. Detectors reference codes from here; the core attaches the `weight` from
 * this table (detectors never supply their own weight). See docs/reason-codes.md.
 *
 * Informational codes (`scoring: false`) always carry weight 0 and never move
 * the score (FR-D-15/16). They annotate; they do not flag.
 */
export const REASON_CODES = {
  // ── Informational (weight 0) ────────────────────────────────────────────
  fqdn_root_label: {
    layer: "lexical",
    family: "dns_name_status",
    scoring: false,
    weight: 0,
    summary:
      "Authority carries an explicit DNS root label (trailing dot, the FQDN form) — valid and resolves identically, but string-comparing allow-lists do not match it.",
  },
  normalization_delta: {
    layer: "lexical",
    family: "idn_form",
    scoring: false,
    weight: 0,
    summary: "Host differs from its normalized/ACE form (any IDN triggers this).",
  },
  confusable_char: {
    layer: "lexical",
    family: "character_identity",
    scoring: false,
    weight: 0,
    summary: "One or more host characters are confusable with another script.",
  },
  confusable_in_path: {
    layer: "lexical",
    family: "character_identity",
    scoring: false,
    weight: 0,
    summary: "One or more path/query characters are confusable with another script.",
  },
  idna_mapping_ambiguity: {
    layer: "lexical",
    family: "character_identity",
    scoring: false,
    weight: 0,
    summary:
      "Host maps to a different ASCII domain under IDNA2003 vs UTS-46/IDNA2008 (or folds to ASCII) — resolver disagreement. Escalates to brand_idna_collapse on an exact brand match.",
  },
  locale_case_ambiguity: {
    layer: "lexical",
    family: "character_identity",
    scoring: false,
    weight: 0,
    summary:
      "Host collapses to a pure-ASCII domain under a Turkish/Azeri lowercase but resolves elsewhere under UTS-46 (İstanbul.com) — a locale-dependent validator/resolver split. Escalates to brand_locale_collapse on an exact brand match.",
  },

  // ── Scoring ─────────────────────────────────────────────────────────────
  mixed_script: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 1,
    summary: "A single host label mixes characters from multiple scripts.",
  },
  invisible_char: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 1,
    summary: "Invisible, zero-width, or control characters appear in the URL.",
  },
  bidi_override: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 1,
    summary: "Bidirectional/RTL override characters appear in the URL.",
  },
  userinfo_present: {
    layer: "lexical",
    family: "authority_delimiters",
    scoring: true,
    weight: 0.5,
    summary: "Authority is hidden behind userinfo (e.g. paypal.com@evil.com).",
  },
  ip_obfuscation: {
    layer: "lexical",
    family: "address_literal",
    scoring: true,
    weight: 0.4,
    summary: "Host is an obfuscated IP (decimal/octal/hex/dotless).",
  },
  ip_loopback: {
    layer: "lexical",
    family: "address_literal",
    scoring: false,
    weight: 0,
    summary:
      "Host is a literal loopback IP (127.0.0.0/8, ::1). Informational (weight 0): destination-range membership, not a claim-(a) finding — reported under architecture §1.1's fourth rule, never scored (§6.1.10, LINK-bwqhvjcs).",
  },
  ip_private: {
    layer: "lexical",
    family: "address_literal",
    scoring: false,
    weight: 0,
    summary:
      "Host is a literal private/internal IP (RFC 1918, fc00::/7). Informational (weight 0): destination-range membership, not a claim-(a) finding — reported under architecture §1.1's fourth rule, never scored (§6.1.10, LINK-bwqhvjcs).",
  },
  ip_link_local: {
    layer: "lexical",
    family: "address_literal",
    scoring: false,
    weight: 0,
    summary:
      "Host is a literal link-local IP (169.254.0.0/16, fe80::/10). Informational (weight 0): destination-range membership, not a claim-(a) finding — reported under architecture §1.1's fourth rule, never scored (§6.1.10, LINK-bwqhvjcs).",
  },
  ip_cloud_metadata: {
    layer: "lexical",
    family: "address_literal",
    scoring: false,
    weight: 0,
    summary:
      "Host is a cloud instance-metadata or provider-internal infrastructure endpoint (169.254.169.254, fd00:ec2::254, 168.63.129.16). Informational (weight 0): destination-range membership, not a claim-(a) finding — reported under architecture §1.1's fourth rule, never scored (§6.1.10, LINK-bwqhvjcs).",
  },
  ssrf_cloud_metadata: {
    layer: "lexical",
    family: "address_literal",
    scoring: true,
    weight: 1,
    summary:
      "Agent context: the host is a cloud instance-metadata or provider-internal infrastructure endpoint — an in-flight SSRF credential-theft target, blocked. Agent-gated (emits only under agentMode).",
  },
  ip_reserved: {
    layer: "lexical",
    family: "address_literal",
    scoring: false,
    weight: 0,
    summary:
      "Host is a literal reserved/special-use IP (0/8, CGNAT, multicast, 240/4). Informational (weight 0): destination-range membership, not a claim-(a) finding — reported under architecture §1.1's fourth rule, never scored (§6.1.10, LINK-bwqhvjcs).",
  },
  ambiguous_numeric_host: {
    layer: "lexical",
    family: "address_literal",
    scoring: true,
    weight: 0.3,
    summary:
      "Host is shaped like a malformed IPv4 (numeric/hex terminal label, no valid canonical IP): a browser rejects it, non-browser clients may resolve it.",
  },
  embedded_domain_in_subdomain: {
    layer: "lexical",
    family: "host_label_arrangement",
    scoring: true,
    weight: 0.5,
    summary: "A domain-looking label sequence sits left of the real registrable domain.",
  },
  file_extension_tld: {
    layer: "lexical",
    family: "file_shape",
    scoring: true,
    weight: 0.4,
    summary:
      "Registrable domain uses a file-extension TLD (.zip/.mov) and is structured to masquerade as a downloadable file.",
  },
  encoding_obfuscation: {
    layer: "lexical",
    family: "percent_escapes",
    scoring: true,
    weight: 0.35,
    summary: "Percent-encoding hides structural characters or is multiply nested.",
  },
  dangerous_scheme: {
    layer: "lexical",
    family: "url_scheme",
    scoring: true,
    weight: 0.9,
    summary: "Scheme can execute or embed content (javascript:, data:, etc.).",
  },
  punycode_malformed: {
    layer: "lexical",
    family: "idn_form",
    scoring: true,
    weight: 0.2,
    summary: "Host has an xn-- label that does not decode to a valid IDN.",
  },
  idna_protocol_violation: {
    layer: "lexical",
    family: "idn_form",
    scoring: true,
    weight: 0.35,
    summary:
      "Host label decodes cleanly but is not permitted under RFC 5892 (IDNA2008): a DISALLOWED code point, a CONTEXTJ/CONTEXTO rule violation, or stacked combining marks. Wider than punycode_malformed, which needs the ACE to fail decoding.",
  },
  percent_encoding_malformed: {
    layer: "lexical",
    family: "percent_escapes",
    scoring: true,
    weight: 0.2,
    summary:
      "A '%' is not followed by two hex digits (RFC 3986 \u00a72.4), so the string declares a percent-escape it does not carry.",
  },
  header_shaped_token: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 0.5,
    summary:
      "Path or query carries an HTTP request-line or header field-line token in wire form (an encoded space before an HTTP-version token, or a field name plus an encoded space plus a value from that field's own grammar), so a component re-emitting the request target undecoded writes a second line on the wire.",
  },
  best_fit_mapping: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 0.5,
    summary:
      "Path or query carries a code point that a Windows ANSI best-fit conversion (WideCharToMultiByte without WC_NO_BEST_FIT_CHARS) replaces with an ASCII delimiter \u2014 a backslash, quote, pipe or slash \u2014 placed between name-shaped tokens, so the consuming process reads a boundary the URL does not declare.",
  },
  ambiguous_authority: {
    layer: "lexical",
    family: "authority_delimiters",
    scoring: true,
    weight: 0.65,
    summary:
      "Authority is structurally ambiguous (multi-@, #@, whitespace, multi-port, backslash, extra-slash, protocol-relative) so parsers disagree on the host.",
  },
  separator_lookalike: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.5,
    summary:
      "Authority uses a delimiter look-alike (fullwidth/ideographic dot or slash) that normalizes to an ASCII separator, hiding the real host.",
  },
  control_char: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 0.6,
    summary:
      "URL carries ASCII control/whitespace characters (raw or percent-encoded CR/LF/TAB/NUL) used to smuggle a protocol or terminate the host.",
  },
  host_length_unresolvable: {
    layer: "lexical",
    family: "dns_name_status",
    scoring: false,
    weight: 0,
    summary:
      "Hostname exceeds a DNS length limit (label > 63 octets or host > 253) and cannot resolve. Informational: nothing is disguised, it simply will not work.",
  },
  special_use_name: {
    layer: "lexical",
    family: "dns_name_status",
    scoring: false,
    weight: 0,
    summary:
      "Host sits under a reserved special-use name (.invalid, .internal, .localhost, .onion, home.arpa, …) — reserved, never delegated in the global DNS root, never publicly resolvable. Informational: nothing is disguised and no reader disagrees.",
  },
  low_byte_truncation: {
    layer: "lexical",
    family: "decoded_bytes",
    scoring: true,
    weight: 0.6,
    summary:
      "A non-ASCII code point wedged between ASCII alphanumerics whose low byte is a dangerous ASCII byte (CR/LF, NUL, TAB, or a URI delimiter) that a lossy UTF-16-to-byte narrowing materializes.",
  },
  ascii_homoglyph: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.2,
    summary:
      "Host label uses ASCII digit look-alikes for letters (g00gle, paypa1) — a same-script disguise the cross-script checks miss.",
  },
  brand_homoglyph: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.8,
    summary:
      "Registrable domain folds via ASCII digit look-alikes (0->o, 1->l, 5->s) to exactly a known brand domain — a high-confidence brand impersonation (paypa1.com, g00gle.com).",
  },
  homograph_skeleton_collision: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.5,
    summary:
      "Registrable domain's UTS#39 confusable skeleton equals a known brand domain exactly — a single-script whole-label homograph (an all-Cyrillic look-alike of a brand) that script-mixing checks cannot see.",
  },
  brand_locale_collapse: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.5,
    summary:
      "Registrable domain collapses to exactly a known brand domain under a Turkish/Azeri lowercase while UTS-46 resolves it elsewhere (tİktok.com) — a locale-dependent validator approves it as the brand, the request reaches the attacker.",
  },
  brand_idna_collapse: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 0.5,
    summary:
      "Host maps to exactly a known brand domain under IDNA2003 while UTS-46/IDNA2008 resolves it elsewhere (wordpreß.com) — a validator on the older standard approves it as the brand, the request reaches the attacker.",
  },
  idn_host: {
    layer: "lexical",
    family: "idn_form",
    scoring: true,
    weight: 0.7,
    summary:
      "Registrable domain is an internationalized (non-ASCII/punycode) domain — blocked by default (idnPolicy 'block'); lands high. Set idnPolicy 'allow' or use idnAllowlist to exempt.",
  },
  homograph_latin_skeleton: {
    layer: "lexical",
    family: "character_identity",
    scoring: true,
    weight: 1,
    summary:
      "Non-Latin registrable domain whose UTS#39 confusable skeleton is pure ASCII-Latin (the Basic Latin block, digits included) — a whole-label homograph masquerading as an ASCII domain (сһаѕе.com→chase.com), no brand list needed.",
  },
  open_redirect_param: {
    layer: "lexical",
    family: "query_payload",
    scoring: true,
    weight: 0.4,
    summary:
      "A known redirect parameter (next/url/redirect…) carries a cross-host URL value, the lexical fingerprint of an open-redirect lure.",
  },
  suspicious_extension: {
    layer: "lexical",
    family: "file_shape",
    scoring: true,
    weight: 0.5,
    summary:
      "URL path ends in a dangerous executable extension (.exe/.scr/.msi…) or a deceptive double-extension (.pdf.exe).",
  },
  excessive_subdomain_depth: {
    layer: "lexical",
    family: "host_label_arrangement",
    scoring: true,
    weight: 0.15,
    summary:
      "Host has an abnormally large number of subdomain labels (≥5) — a low-weight combination signal for a buried registrable domain.",
  },
  prompt_injection_url: {
    layer: "lexical",
    family: "query_payload",
    scoring: false,
    weight: 0,
    summary:
      "URL carries an LLM-agent prompt-injection payload: a prompt-control query parameter (role=/system=/prompt=) or an instruction-override path segment (/ignore-previous-instructions). Agent-gated (emits only under agentMode). Informational (weight 0): a reader-consumption property, reported under architecture §1.1's fourth rule, never scored.",
  },
  credential_harvesting: {
    layer: "lexical",
    family: "query_payload",
    scoring: false,
    weight: 0,
    summary:
      "URL has an OAuth/token-flow shape: a /oauth/authorize-style path or a redirect_uri=/access_token=/client_secret=/code=+client_id= query. Reported for EVERY host, github.com included. Agent-gated (emits only under agentMode). Informational (weight 0): the flow shape is a string fact, the impostor half was an inverse provider allowlist and is gone (§1.1, LINK-uyoocslu).",
  },
  data_exfiltration: {
    layer: "lexical",
    family: "query_payload",
    scoring: false,
    weight: 0,
    summary:
      "URL query carries a data-exfiltration shape: an exfil-marker parameter (exfil=/beacon=/dump=/leak=/payload=) with a value, or any parameter carrying an abnormally long opaque base64/hex-style token — context/secrets smuggled out in the URL. Agent-gated (emits only under agentMode). Informational (weight 0): a reader-consumption property, reported under architecture §1.1's fourth rule, never scored.",
  },

  // ── Resolution (Layer 2 observed corroboration, weight 0) ────────────────
  open_redirect_observed: {
    layer: "resolution",
    family: "query_payload",
    scoring: false,
    weight: 0,
    summary:
      "A resolved redirect chain was observed to leave the input's registrable domain and land on the domain named by an open_redirect_param payload — resolution-time corroboration of the lexical suspicion, not proof of general exploitability. Informational (weight 0): it never re-scores the lexical open_redirect_param signal.",
  },
  content_type_mismatch: {
    layer: "resolution",
    family: "response_content",
    scoring: false,
    weight: 0,
    summary:
      "A resolved response's bytes sniff to an active/executable type (html/xml) that diverges from the declared Content-Type with no nosniff — resolution-time content-type-spoofing corroboration, informational (weight 0).",
  },
  https_downgrade_observed: {
    layer: "resolution",
    family: "url_scheme",
    scoring: false,
    weight: 0,
    summary:
      "A resolved chain transitioned from an https: hop to an http: target (HTTP redirect, Refresh header, or meta refresh) — the chain left TLS for plaintext. Reported, never refused. Informational (weight 0): the chain does not misrepresent itself, so this is a fact worth reporting, not a claim that the URL is deceptive.",
  },

  // ── Reputation (Layer 3 source-attributed, conjunctive) ──────────────────
  young_domain_brand_risk: {
    layer: "reputation",
    family: "character_identity",
    scoring: true,
    weight: 0.5,
    summary:
      "RDAP registration age for the ICANN registrable domain is below the young-domain threshold AND the domain already carries a lexical brand-impersonation signal (homoglyph/skeleton/api-endpoint) — a conjunctive age × brand risk. Age alone is only evidence; this fires only with lexical corroboration, computes age on the registrable domain so ancient shared-hosting parents never read as young, and never duplicates the lexical brand reason.",
  },
  malware_url_listed: {
    layer: "reputation",
    family: "reputation_listing",
    scoring: true,
    weight: 1,
    summary:
      "The exact URL matches a record in a caller-owned URLhaus mirror snapshot that is currently listed online AND the snapshot is within its declared freshness — an authoritative, subject-tied malware-distribution match. The match is exact-URL only (never broadened to the host), so an offline/expired record or a stale snapshot stays evidence-only and a path/query mismatch is a no-hit; absence is never a safety claim.",
  },
  verified_phish_listed: {
    layer: "reputation",
    family: "reputation_listing",
    scoring: true,
    weight: 1,
    summary:
      "The exact URL matches a record in a caller-owned PhishTank mirror snapshot that is human-verified AND currently online AND the snapshot is within its declared freshness — an authoritative, subject-tied phishing match. The match is exact-URL only (never broadened to the host), so an unverified/offline/removed record or a stale snapshot stays evidence-only and a path/query mismatch is a no-hit; absence is never a safety claim.",
  },

  // ── Policy (caller-configured, weight 0) ─────────────────────────────────
  tld_denied: {
    layer: "policy",
    family: "policy_tld",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's TLD is on the caller's deny-list. Advisory only (weight 0) — a policy verdict the caller asked for, not a deception finding. Since LINK-brsntven this is the ONLY TLD-membership channel: linklint ships no curated high-abuse TLD list of its own.",
  },
  tld_not_allowlisted: {
    layer: "policy",
    family: "policy_tld",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's TLD is not on the caller's allow-list. Advisory only (weight 0) — a policy verdict the caller asked for, not a deception finding. Since LINK-brsntven this is the ONLY TLD-membership channel: linklint ships no curated high-abuse TLD list of its own.",
  },
  host_denied: {
    layer: "policy",
    family: "policy_host",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's registrable domain is on the caller's deny-list (covers all its subdomains). Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },
  host_not_allowlisted: {
    layer: "policy",
    family: "policy_host",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's registrable domain is not on the caller's allow-list (default-deny corporate lockdown). Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },
  scheme_denied: {
    layer: "policy",
    family: "url_scheme",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the input's scheme is on the caller's deny-list or not on the allow-list (e.g. https-only lockdown). Advisory only (weight 0) — a separate policy channel, distinct from the built-in dangerous_scheme deception detector.",
  },
  port_denied: {
    layer: "policy",
    family: "policy_port",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the input's explicit port is on the caller's deny-list or is non-standard for its scheme. Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },

  // ── Meta ────────────────────────────────────────────────────────────────
  parse_error: {
    layer: "lexical",
    family: "parse_failure",
    scoring: false,
    weight: 0,
    summary: "Input is not a parseable URL or hostname.",
  },
} as const satisfies Record<string, ReasonCodeMeta>;

/** Union of every valid reason code. */
export type ReasonCode = keyof typeof REASON_CODES;

/** Look up registry metadata for a code. */
export function reasonMeta(code: ReasonCode): ReasonCodeMeta {
  return REASON_CODES[code];
}

/** The weight the core attaches for a given code. */
export function weightFor(code: ReasonCode): number {
  return REASON_CODES[code].weight;
}

/** The correlation family a code belongs to. See {@link REASON_FAMILIES}. */
export function familyFor(code: ReasonCode): ReasonFamily {
  return REASON_CODES[code].family;
}

/**
 * The codes that read a given feature, in registry order.
 *
 * The grouping surface: a caller rendering `reasons[]` uses this to say "one
 * feature, four readings" instead of listing four findings that look separate.
 */
export function codesInFamily(family: ReasonFamily): ReasonCode[] {
  return (Object.keys(REASON_CODES) as ReasonCode[]).filter(
    (code) => REASON_CODES[code].family === family,
  );
}

/**
 * Total order over `Reason`s: descending weight, then ascending reason code.
 *
 * The code tie-break is a **codepoint** comparison, deliberately NOT
 * `String.prototype.localeCompare`. `localeCompare` without an explicit locale
 * argument resolves against the ambient ICU/host locale, so the same equal-weight
 * reasons sorted on a `cs`, `sk`, `az`, `lt`, `lv`, or `th` machine come out in a
 * different order than on an `en-US` one — reordering `result.reasons` purely as
 * a function of who ran the check. Reason codes are ASCII `[a-z0-9_]` identifiers,
 * so `<`/`>` is the correct and fully locale-independent comparator, and it keeps
 * the documented determinism guarantee (docs/architecture.md) machine-independent.
 *
 * Same bug class as the locale-tailored case mapping audited in
 * docs/locale-case-mapping.md: never let an ambient locale reach a step that
 * decides identity or output shape.
 */
export function compareReasons(a: { weight: number; code: string }, b: { weight: number; code: string }): number {
  if (b.weight !== a.weight) return b.weight - a.weight;
  return a.code < b.code ? -1 : a.code > b.code ? 1 : 0;
}
