import type { Layer } from "./types.js";

/**
 * Reason-code registry — the single source of truth for every code linklint can
 * emit. Detectors reference codes from here; the core attaches the `weight` from
 * this table (detectors never supply their own weight). See docs/reason-codes.md.
 *
 * Informational codes (`scoring: false`) always carry weight 0 and never move
 * the score (FR-D-15/16). They annotate; they do not flag.
 */
export interface ReasonCodeMeta {
  /** Inspection layer the code belongs to. v1 codes are all `lexical`. */
  layer: Layer;
  /** Whether the code contributes to the risk score. */
  scoring: boolean;
  /** Version-pinned weight in [0,1]. Always 0 for informational codes. */
  weight: number;
  /** One-line summary for docs and UI surfaces. */
  summary: string;
}

export const REASON_CODES = {
  // ── Informational (weight 0) ────────────────────────────────────────────
  normalization_delta: {
    layer: "lexical",
    scoring: false,
    weight: 0,
    summary: "Host differs from its normalized/ACE form (any IDN triggers this).",
  },
  confusable_char: {
    layer: "lexical",
    scoring: false,
    weight: 0,
    summary: "One or more host characters are confusable with another script.",
  },
  confusable_in_path: {
    layer: "lexical",
    scoring: false,
    weight: 0,
    summary: "One or more path/query characters are confusable with another script.",
  },
  idna_mapping_ambiguity: {
    layer: "lexical",
    scoring: false,
    weight: 0,
    summary:
      "Host maps to a different ASCII domain under IDNA2003 vs UTS-46/IDNA2008 (or folds to ASCII) — resolver disagreement. Scoring escalation lands with the Epic G brand list.",
  },

  // ── Scoring ─────────────────────────────────────────────────────────────
  mixed_script: {
    layer: "lexical",
    scoring: true,
    weight: 1,
    summary: "A single host label mixes characters from multiple scripts.",
  },
  invisible_char: {
    layer: "lexical",
    scoring: true,
    weight: 1,
    summary: "Invisible, zero-width, or control characters appear in the URL.",
  },
  bidi_override: {
    layer: "lexical",
    scoring: true,
    weight: 1,
    summary: "Bidirectional/RTL override characters appear in the URL.",
  },
  userinfo_present: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary: "Authority is hidden behind userinfo (e.g. paypal.com@evil.com).",
  },
  ip_obfuscation: {
    layer: "lexical",
    scoring: true,
    weight: 0.4,
    summary: "Host is an obfuscated IP (decimal/octal/hex/dotless).",
  },
  ip_loopback: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary: "Host is a literal loopback IP (127.0.0.0/8, ::1).",
  },
  ip_private: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary: "Host is a literal private/internal IP (RFC 1918, fc00::/7).",
  },
  ip_link_local: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary: "Host is a literal link-local IP (169.254.0.0/16, fe80::/10).",
  },
  ip_cloud_metadata: {
    layer: "lexical",
    scoring: true,
    weight: 0.75,
    summary: "Host is the cloud instance-metadata endpoint (169.254.169.254, fd00:ec2::254).",
  },
  ssrf_cloud_metadata: {
    layer: "lexical",
    scoring: true,
    weight: 1,
    summary:
      "Agent context: the host is the cloud instance-metadata endpoint — an in-flight SSRF credential-theft target, blocked. Agent-gated (emits only under agentMode).",
  },
  ip_reserved: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary: "Host is a literal reserved/special-use IP (0/8, CGNAT, multicast, 240/4).",
  },
  ambiguous_numeric_host: {
    layer: "lexical",
    scoring: true,
    weight: 0.3,
    summary:
      "Host is shaped like a malformed IPv4 (numeric/hex terminal label, no valid canonical IP): a browser rejects it, non-browser clients may resolve it.",
  },
  embedded_domain_in_subdomain: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary: "A domain-looking label sequence sits left of the real registrable domain.",
  },
  risky_tld: {
    layer: "lexical",
    scoring: true,
    weight: 0.15,
    summary: "Registrable domain uses a high-abuse TLD (low-weight contextual signal).",
  },
  file_extension_tld: {
    layer: "lexical",
    scoring: true,
    weight: 0.4,
    summary:
      "Registrable domain uses a file-extension TLD (.zip/.mov) and is structured to masquerade as a downloadable file.",
  },
  encoding_obfuscation: {
    layer: "lexical",
    scoring: true,
    weight: 0.35,
    summary: "Percent-encoding hides structural characters or is multiply nested.",
  },
  dangerous_scheme: {
    layer: "lexical",
    scoring: true,
    weight: 0.9,
    summary: "Scheme can execute or embed content (javascript:, data:, etc.).",
  },
  punycode_malformed: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary: "Host has an xn-- label that does not decode to a valid IDN.",
  },
  ambiguous_authority: {
    layer: "lexical",
    scoring: true,
    weight: 0.65,
    summary:
      "Authority is structurally ambiguous (multi-@, #@, whitespace, multi-port, backslash, extra-slash, protocol-relative) so parsers disagree on the host.",
  },
  separator_lookalike: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "Authority uses a delimiter look-alike (fullwidth/ideographic dot or slash) that normalizes to an ASCII separator, hiding the real host.",
  },
  control_char: {
    layer: "lexical",
    scoring: true,
    weight: 0.6,
    summary:
      "URL carries ASCII control/whitespace characters (raw or percent-encoded CR/LF/TAB/NUL) used to smuggle a protocol or terminate the host.",
  },
  ascii_homoglyph: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary:
      "Host label uses ASCII digit look-alikes for letters (g00gle, paypa1) — a same-script disguise the cross-script checks miss.",
  },
  brand_homoglyph: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "Registrable domain folds via ASCII digit look-alikes (0->o, 1->l, 5->s) to exactly a known brand domain — a high-confidence brand impersonation (paypa1.com, g00gle.com).",
  },
  brand_lookalike: {
    layer: "lexical",
    scoring: true,
    weight: 0.4,
    summary:
      "Registrable domain is a transposition-aware edit-distance near-miss (1–2) of a known brand domain — a typosquat (gogole.com, microsoftt.com, paypal.co).",
  },
  homograph_skeleton_collision: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "Registrable domain's UTS#39 confusable skeleton equals a known brand domain exactly — a single-script whole-label homograph (an all-Cyrillic look-alike of a brand) that script-mixing checks cannot see.",
  },
  idn_host: {
    layer: "lexical",
    scoring: true,
    weight: 0.7,
    summary:
      "Registrable domain is an internationalized (non-ASCII/punycode) domain — blocked by default (idnPolicy 'block'); lands high. Set idnPolicy 'allow' or use idnAllowlist to exempt.",
  },
  homograph_latin_skeleton: {
    layer: "lexical",
    scoring: true,
    weight: 1,
    summary:
      "Non-Latin registrable domain whose UTS#39 confusable skeleton is pure ASCII-Latin — a whole-label homograph masquerading as an ASCII domain (сһаѕе.com→chase.com), no brand list needed.",
  },
  brand_soundsquat: {
    layer: "lexical",
    scoring: true,
    weight: 0.3,
    summary:
      "Registrable label is a phonetic homophone of a known brand (netflicks->netflix, dropboks->dropbox) — a soundsquat invisible to edit-distance and digit-fold checks.",
  },
  brand_bitsquat: {
    layer: "lexical",
    scoring: true,
    weight: 0.15,
    summary:
      "Registrable label is a single-bit-flip neighbor of a known brand (netfliz->netflix, amazgn->amazon) — a bitsquat (memory/transmission-error attack class), low-weight combination signal.",
  },
  bait_tokens: {
    layer: "lexical",
    scoring: true,
    weight: 0.15,
    summary:
      "Host/path stacks multiple distinct phishing-bait keywords (secure, verify, account, login…) — a low-weight density signal that corroborates the brand-impersonation checks.",
  },
  open_redirect_param: {
    layer: "lexical",
    scoring: true,
    weight: 0.4,
    summary:
      "A known redirect parameter (next/url/redirect…) carries a cross-host URL value, the lexical fingerprint of an open-redirect lure.",
  },
  suspicious_extension: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "URL path ends in a dangerous executable extension (.exe/.scr/.msi…) or a deceptive double-extension (.pdf.exe).",
  },
  excessive_subdomain_depth: {
    layer: "lexical",
    scoring: true,
    weight: 0.15,
    summary:
      "Host has an abnormally large number of subdomain labels (≥5) — a low-weight combination signal for a buried registrable domain.",
  },
  prompt_injection_url: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "URL carries an LLM-agent prompt-injection payload: a prompt-control query parameter (role=/system=/prompt=) or an instruction-override path segment (/ignore-previous-instructions). Agent-gated (emits only under agentMode).",
  },
  api_endpoint_impersonation: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary:
      "Host masquerades as a known API provider's endpoint — an api-brands token (openai/anthropic/…) appears in a host label whose registrable domain is not the real provider (api.openai-com.io), optionally with a real API route path. Agent-gated (emits only under agentMode).",
  },
  credential_harvesting: {
    layer: "lexical",
    scoring: true,
    weight: 0.35,
    summary:
      "URL has an OAuth/token-flow shape (a /oauth/authorize-style path or a redirect_uri=/access_token=/client_secret=/code=+client_id= query) on a host that is NOT a known OAuth/identity provider — a credential-phishing / token-exfiltration URL shape. Agent-gated (emits only under agentMode).",
  },
  data_exfiltration: {
    layer: "lexical",
    scoring: true,
    weight: 0.3,
    summary:
      "URL query carries a data-exfiltration shape: an exfil-marker parameter (data=/exfil=/beacon=/dump=/leak=/payload=) with a value, or any parameter carrying an abnormally long opaque base64/hex-style token — context/secrets smuggled out in the URL. Agent-gated (emits only under agentMode).",
  },

  // ── Resolution (Layer 2 observed corroboration, weight 0) ────────────────
  open_redirect_observed: {
    layer: "resolution",
    scoring: false,
    weight: 0,
    summary:
      "A resolved redirect chain was observed to leave the input's registrable domain and land on the domain named by an open_redirect_param payload — resolution-time corroboration of the lexical suspicion, not proof of general exploitability. Informational (weight 0): it never re-scores the lexical open_redirect_param signal.",
  },

  // ── Policy (caller-configured, weight 0) ─────────────────────────────────
  tld_denied: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's TLD is on the caller's deny-list. Advisory only (weight 0) — distinct from the built-in risky_tld deception heuristic.",
  },
  tld_not_allowlisted: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's TLD is not on the caller's allow-list. Advisory only (weight 0) — distinct from the built-in risky_tld deception heuristic.",
  },
  host_denied: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's registrable domain is on the caller's deny-list (covers all its subdomains). Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },
  host_not_allowlisted: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the host's registrable domain is not on the caller's allow-list (default-deny corporate lockdown). Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },
  scheme_denied: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the input's scheme is on the caller's deny-list or not on the allow-list (e.g. https-only lockdown). Advisory only (weight 0) — a separate policy channel, distinct from the built-in dangerous_scheme deception detector.",
  },
  port_denied: {
    layer: "policy",
    scoring: false,
    weight: 0,
    summary:
      "Caller-configured: the input's explicit port is on the caller's deny-list or is non-standard for its scheme. Advisory only (weight 0) — a separate policy channel, not a deception signal.",
  },

  // ── Meta ────────────────────────────────────────────────────────────────
  parse_error: {
    layer: "lexical",
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
