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
    weight: 0.4,
    summary: "A single host label mixes characters from multiple scripts.",
  },
  invisible_char: {
    layer: "lexical",
    scoring: true,
    weight: 0.5,
    summary: "Invisible, zero-width, or control characters appear in the URL.",
  },
  bidi_override: {
    layer: "lexical",
    scoring: true,
    weight: 0.6,
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
  brand_in_path: {
    layer: "lexical",
    scoring: true,
    weight: 0.2,
    summary:
      "A brand reference is planted in the path/query of an unrelated host (evil.com/paypal.com/login).",
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
