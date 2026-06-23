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
    // BLOCKER (weight 1.0). A single host label mixing scripts (Cyrillic+Latin
    // etc.) has NO legitimate use — real IDNs are single-script (the detector
    // already de-noises on this). Maintainer directive: this should effectively
    // block, so it is weighted 1.0 — the probabilistic-OR product zeroes and the
    // score saturates to 1 (critical) regardless of context.
    weight: 1,
    summary: "A single host label mixes characters from multiple scripts.",
  },
  invisible_char: {
    layer: "lexical",
    scoring: true,
    // BLOCKER (weight 1.0). Invisible / zero-width / control characters in a URL
    // are an obfuscation technique with no legitimate use. Maintainer directive:
    // block — weighted 1.0 (saturates the score to critical).
    weight: 1,
    summary: "Invisible, zero-width, or control characters appear in the URL.",
  },
  bidi_override: {
    layer: "lexical",
    scoring: true,
    // BLOCKER (weight 1.0). Bidi/RTL override characters manipulate the rendered
    // reading direction to disguise the URL — no legitimate use. Maintainer
    // directive: block — weighted 1.0 (saturates the score to critical).
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
    // Literal-IP range classifier. A loopback host (127.0.0.0/8, ::1) is an
    // internal target a public-facing URL has no legitimate reason to name —
    // the lexical fingerprint of an SSRF lure. Weighted LOW (a literal private
    // IP is suspicious-in-context, not decisive on its own) and below the cloud-
    // metadata bucket. Provisional — re-tuned against the corpus.
    weight: 0.2,
    summary: "Host is a literal loopback IP (127.0.0.0/8, ::1).",
  },
  ip_private: {
    layer: "lexical",
    scoring: true,
    // Literal-IP range classifier. An RFC 1918 / unique-local host
    // (10/8, 172.16/12, 192.168/16, fc00::/7) names an internal target. Same
    // low-weight, suspicious-in-context band as ip_loopback.
    weight: 0.2,
    summary: "Host is a literal private/internal IP (RFC 1918, fc00::/7).",
  },
  ip_link_local: {
    layer: "lexical",
    scoring: true,
    // Literal-IP range classifier. A link-local host (169.254.0.0/16, fe80::/10)
    // names an unrouteable internal target. Same low band as the other generic
    // private buckets, below cloud-metadata.
    weight: 0.2,
    summary: "Host is a literal link-local IP (169.254.0.0/16, fe80::/10).",
  },
  ip_cloud_metadata: {
    layer: "lexical",
    scoring: true,
    // Literal-IP range classifier — the most specific bucket. The cloud
    // instance-metadata endpoint (169.254.169.254, fd00:ec2::254, and IPv4-mapped
    // equivalents) is the canonical SSRF credential-theft target; a URL naming it
    // literally is a near-unambiguous exfiltration attempt. Weighted 0.75 so it
    // lands HIGH on its own (it blocks the default `--fail-on high` gate) — well
    // above the generic private/loopback buckets, but short of `critical`, which
    // is reserved for the agentMode SSRF escalation (ssrf_cloud_metadata) where a
    // fetch is actually in flight. Dual-use (cloud-init, IaC) so not a hard block
    // in the default verdict.
    weight: 0.75,
    summary: "Host is the cloud instance-metadata endpoint (169.254.169.254, fd00:ec2::254).",
  },
  ssrf_cloud_metadata: {
    layer: "lexical",
    scoring: true,
    // AGENT-GATED escalation (emits only when InspectOptions.agentMode is true).
    // In an agent / tool-use context a URL naming the cloud instance-metadata
    // endpoint is an in-flight SSRF credential-theft attempt with no defensible
    // purpose — so it BLOCKS (weight 1.0 → saturates the score to critical). It
    // stacks on the always-on ip_cloud_metadata (0.75): the classifier states the
    // fact, this states the agent-context verdict. Default (non-agent) callers —
    // log scanners, cloud-ops tooling that legitimately names the endpoint — keep
    // the high (overridable) ip_cloud_metadata verdict and never see this.
    weight: 1,
    summary:
      "Agent context: the host is the cloud instance-metadata endpoint — an in-flight SSRF credential-theft target, blocked. Agent-gated (emits only under agentMode).",
  },
  ip_reserved: {
    layer: "lexical",
    scoring: true,
    // Literal-IP range classifier. A reserved / special-use host (0.0.0.0/8,
    // 100.64/10 CGNAT, multicast, 240/4, ::, ff00::/8) is not a normal public
    // destination. Same low band as the other generic IP buckets.
    weight: 0.2,
    summary: "Host is a literal reserved/special-use IP (0/8, CGNAT, multicast, 240/4).",
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
    // Highest-confidence brand impersonation: the registrable domain
    // folds via ASCII digit look-alikes (0->o, 1->l, 5->s) to EXACTLY a watchlist
    // brand domain (paypa1.com -> paypal.com, g00gle.com -> google.com). Weighted
    // above brand_lookalike — an exact skeleton match is more decisive than a
    // fuzzy near-miss. Provisional — re-tuned against the full corpus.
    weight: 0.5,
    summary:
      "Registrable domain folds via ASCII digit look-alikes (0->o, 1->l, 5->s) to exactly a known brand domain — a high-confidence brand impersonation (paypa1.com, g00gle.com).",
  },
  brand_lookalike: {
    layer: "lexical",
    scoring: true,
    // Tuned to the userinfo_present (0.5) / ip_obfuscation (0.4) band as a
    // strong-but-not-decisive standalone signal; a fuzzy near-miss of a known
    // brand domain is a deliberate typosquat far more often than chance. Kept
    // below brand_homoglyph (an exact skeleton match is higher confidence).
    // Provisional — re-tuned against the full corpus.
    weight: 0.4,
    summary:
      "Registrable domain is a transposition-aware edit-distance near-miss (1–2) of a known brand domain — a typosquat (gogole.com, microsoftt.com, paypal.co).",
  },
  homograph_skeleton_collision: {
    layer: "lexical",
    scoring: true,
    // The registrable domain's UTS#39 confusable
    // skeleton equals a watchlist brand domain exactly: a single-script,
    // all-confusable look-alike (e.g. an all-Cyrillic `сһаѕе.com`) that
    // `mixed_script` cannot see (no script mixing) and confusable annotation
    // only flags at weight 0. An exact skeleton == brand collision is
    // decisive, so it sits in the same band as brand_homoglyph (0.5).
    // Mutually exclusive with brand_homoglyph by construction (that owns the
    // pure-ASCII digit-fold case; this runs only on non-ASCII hosts).
    // Provisional — re-tuned with the brand family against the full corpus.
    weight: 0.5,
    summary:
      "Registrable domain's UTS#39 confusable skeleton equals a known brand domain exactly — a single-script whole-label homograph (an all-Cyrillic look-alike of a brand) that script-mixing checks cannot see.",
  },
  idn_host: {
    layer: "lexical",
    scoring: true,
    // POLICY-GATED scoring signal. The registrable domain is an internationalized
    // domain (carries a non-ASCII label). Blocked by DEFAULT (idnPolicy "block"):
    // for a Western-market audience a Unicode/punycode domain is almost always
    // accidental. Weighted 0.7 so it lands HIGH on its own — enough to fail the
    // default `--fail-on high` gate (an effective block) while leaving `critical`
    // to the unambiguous homograph/script attacks. Suppressed entirely under
    // idnPolicy "allow", or per-domain via idnAllowlist. The dangerous IDN subset
    // is already critical via mixed_script / homograph_latin_skeleton regardless.
    weight: 0.7,
    summary:
      "Registrable domain is an internationalized (non-ASCII/punycode) domain — blocked by default (idnPolicy 'block'); lands high. Set idnPolicy 'allow' or use idnAllowlist to exempt.",
  },
  homograph_latin_skeleton: {
    layer: "lexical",
    scoring: true,
    // BLOCKER (weight 1.0). Target-LESS whole-label homograph: a non-ASCII
    // registrable domain whose UTS#39 confusable skeleton is PURE ASCII-Latin
    // (every character a Latin look-alike), so it reads to a human as an ASCII
    // domain — сһаѕе.com→chase.com, ехямрӏе.com→example.com. Unlike
    // homograph_skeleton_collision this needs no brand list; a genuine non-Latin
    // word retains a non-Latin character in its skeleton and never fires.
    // Maintainer directive: "pure unicode that looks like ASCII → block", so it
    // is weighted 1.0 (saturates the score to critical). Legitimate IDN owners
    // use the caller IDN allow-list to override.
    weight: 1,
    summary:
      "Non-Latin registrable domain whose UTS#39 confusable skeleton is pure ASCII-Latin — a whole-label homograph masquerading as an ASCII domain (сһаѕе.com→chase.com), no brand list needed.",
  },
  brand_soundsquat: {
    layer: "lexical",
    scoring: true,
    // The registrable label is a PHONETIC homophone of a
    // watchlist brand (netflicks → netflix, dropboks → dropbox): same sound,
    // but invisible to edit-distance / digit-fold checks. Provisional weight
    // 0.3 — BELOW brand_lookalike (0.4) because phonetic-key matching is lossier
    // and noisier than bounded edit distance, yet ABOVE the low band (a
    // whole-label sound-key match against a real brand is a deliberate
    // soundsquat far more often than chance). Re-tuned with the brand family
    // against the full corpus.
    weight: 0.3,
    summary:
      "Registrable label is a phonetic homophone of a known brand (netflicks->netflix, dropboks->dropbox) — a soundsquat invisible to edit-distance and digit-fold checks.",
  },
  brand_bitsquat: {
    layer: "lexical",
    scoring: true,
    // The registrable label is a single-bit-flip neighbor of a
    // watchlist brand (netfliz -> netflix, amazgn -> amazon): the memory/
    // transmission-error attack class. A bit-flip is by construction also an
    // edit-distance-1 neighbor, so this usually STACKS with brand_lookalike
    // (distinct code naming the specific attack). It is a real but NICHE,
    // combination-only signal — never decisive standalone — so it is weighted LOW,
    // in the risky_tld / bait_tokens / excessive_subdomain_depth (0.15) band.
    // Provisional — re-tuned with the brand family against the full corpus.
    weight: 0.15,
    summary:
      "Registrable label is a single-bit-flip neighbor of a known brand (netfliz->netflix, amazgn->amazon) — a bitsquat (memory/transmission-error attack class), low-weight combination signal.",
  },
  bait_tokens: {
    layer: "lexical",
    scoring: true,
    // Phishing-bait keyword density in host/path. A weak corroborating
    // signal, never decisive on its own: legit login/account pages carry these
    // words routinely, so this is weighted LOW (the risky_tld / excessive_
    // subdomain_depth 0.15 band) and only fires on a HIGH density. It complements
    // the brand-impersonation checks. Provisional — re-tuned against the full corpus.
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
    // AGENT-GATED detector (emits only when InspectOptions.agentMode is true).
    // The URL carries an LLM-agent prompt-control payload: a prompt-control query
    // parameter (role=/system=/prompt=…) or an instruction-override path segment
    // (/ignore-previous-instructions…). This is the highest false-positive surface
    // of any detector — these tokens also appear in legitimate apps — which is
    // exactly WHY it is gated off the default verdict. Weighted in the
    // strong-but-not-decisive band (0.5): a deliberate injection payload is a real
    // signal in an agent context, but never decisive standalone. Provisional —
    // re-tuned with the agent corpus (V4e).
    weight: 0.5,
    summary:
      "URL carries an LLM-agent prompt-injection payload: a prompt-control query parameter (role=/system=/prompt=) or an instruction-override path segment (/ignore-previous-instructions). Agent-gated (emits only under agentMode).",
  },
  api_endpoint_impersonation: {
    layer: "lexical",
    scoring: true,
    // AGENT-GATED detector (emits only when InspectOptions.agentMode is true).
    // A host masquerades as a known API provider's endpoint: an api-brands tier
    // token (openai/anthropic/…) appears as an exact host label while the
    // registrable domain is NOT the real provider (api.openai-com.io). Pointing an
    // agent's API client at a look-alike endpoint is high-confidence impersonation
    // — an exact brand-token-on-wrong-eTLD+1 match — so it sits in the
    // brand-impersonation band alongside brand_homoglyph (0.5), above the fuzzier
    // brand_lookalike (0.4). Path escalation (a real API route) only sharpens the
    // detail; the weight is unchanged. Provisional — re-tuned with the agent
    // corpus (V4e).
    weight: 0.5,
    summary:
      "Host masquerades as a known API provider's endpoint — an api-brands token (openai/anthropic/…) appears in a host label whose registrable domain is not the real provider (api.openai-com.io), optionally with a real API route path. Agent-gated (emits only under agentMode).",
  },
  credential_harvesting: {
    layer: "lexical",
    scoring: true,
    // AGENT-GATED detector (emits only when InspectOptions.agentMode is true).
    // The URL has an OAuth / token-flow SHAPE (a `/oauth/authorize`-style path
    // segment or a token-flow query parameter — redirect_uri=/access_token=/
    // client_secret=/response_type=token/code=+client_id=) on a host whose
    // registrable domain is NOT a known OAuth/identity provider. These markers
    // are perfectly legitimate on the real providers (accounts.google.com,
    // github.com), which is exactly why the detector is gated AND keyed on the
    // non-allowlisted-host condition. Weighted in the MEDIUM band (0.35), BELOW
    // the brand-impersonation band (0.5): an OAuth shape on an unknown host is
    // suspicious but legitimate apps DO implement OAuth, so it is a strong
    // corroborating signal that stacks with brand/api impersonation (probabilistic
    // OR) rather than a decisive standalone flag. Sits alongside the
    // encoding_obfuscation (0.35) band. Provisional — re-tuned with the agent
    // corpus (V4e).
    weight: 0.35,
    summary:
      "URL has an OAuth/token-flow shape (a /oauth/authorize-style path or a redirect_uri=/access_token=/client_secret=/code=+client_id= query) on a host that is NOT a known OAuth/identity provider — a credential-phishing / token-exfiltration URL shape. Agent-gated (emits only under agentMode).",
  },
  data_exfiltration: {
    layer: "lexical",
    scoring: true,
    // AGENT-GATED detector (emits only when InspectOptions.agentMode is true).
    // The query carries a data-exfiltration SHAPE: a parameter whose NAME is an
    // exfil marker (data=/exfil=/beacon=/dump=/leak=/payload=) with a non-empty
    // value, OR any parameter whose value is an abnormally long (>=200-char),
    // opaque, high-density base64/hex-style blob — the shape of context/secrets
    // smuggled out in the URL. The overlong-token path pairs a conservative length
    // floor with an opaqueness gate (no spaces, opaque alphabet, >=0.9 alnum
    // density) so ordinary long query values (search strings, JWTs in legit flows)
    // do not trip it. "Medium priority" per PRD: weighted in the LOWER band (0.3),
    // just below credential_harvesting (0.35) and the encoding_obfuscation band —
    // an exfil-shaped query is a real but not decisive standalone signal (legit
    // apps DO post long opaque tokens and use params named `data`), so it
    // corroborates / stacks rather than flagging alone. Provisional — re-tuned with
    // the agent corpus (V4e).
    weight: 0.3,
    summary:
      "URL query carries a data-exfiltration shape: an exfil-marker parameter (data=/exfil=/beacon=/dump=/leak=/payload=) with a value, or any parameter carrying an abnormally long opaque base64/hex-style token — context/secrets smuggled out in the URL. Agent-gated (emits only under agentMode).",
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
