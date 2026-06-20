/**
 * Stable, versioned result contract returned by every linklint channel.
 *
 * See docs/PRD.md §5.3 (FR-SCORE-*) and docs/architecture.md §6.
 * The shape is identical for the library and the MCP server.
 */

/** Current schema version. Bumped only on a breaking change to this contract. */
export const SCHEMA_VERSION = "1.0" as const;

/**
 * Conceptual inspection layers. v1 implements `lexical` only.
 *
 * `policy` is a separate, caller-configured channel: policy reasons appear in
 * `reasons[]` but always carry `weight: 0`, so they annotate without moving the
 * deception score or severity (see {@link InspectOptions}).
 */
export type Layer = "lexical" | "resolution" | "reputation" | "policy";

/** Top-level disposition of an inspection. */
export type Status = "ok" | "invalid";

/**
 * Severity bands derived from `score` (FR-SCORE-1b). `null` only on invalid
 * input, where no score could be computed.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Parsed URL components surfaced on an `ok` result. `null` on invalid input. */
export interface ParsedUrl {
  /** Lower-cased scheme without the trailing colon, or `null` if none present. */
  scheme: string | null;
  /** The userinfo (`user:pass`) segment before `@`, or `null`. */
  userinfo: string | null;
  /** The host as it appears in the authority (U-label form where applicable). */
  effectiveHost: string | null;
  /** Registrable domain (eTLD+1) per the Public Suffix List, or `null`. */
  registrableDomain: string | null;
  /** Public suffix (eTLD) per the PSL, or `null`. */
  publicSuffix: string | null;
  /** Subdomain labels left of the registrable domain (may be empty string). */
  subdomain: string | null;
  /** Host split into labels, left-to-right. Empty for IP / hostless inputs. */
  hostLabels: string[];
  /** Numeric port, or `null` when not explicitly present. */
  port: number | null;
  /** Path component (may be empty string). */
  path: string;
  /** Query string without the leading `?`, or `null`. */
  query: string | null;
  /** Fragment without the leading `#`, or `null`. */
  fragment: string | null;
  /** True when the effective host is an IP literal (v4 or v6). */
  isIp: boolean;
}

/**
 * A single named finding. `weight` is the score contribution attached by the
 * core from the version-pinned weights table — detectors never supply it.
 * Informational reasons carry `weight: 0`.
 */
export interface Reason {
  code: string;
  layer: Layer;
  detail: string;
  weight: number;
}

/** Which URL component a confusable character was found in. */
export type ConfusableComponent = "host" | "path" | "query";

/**
 * Per-character confusable finding. A structured expansion of the
 * `confusable_char` / `confusable_in_path` reasons (FR-SCORE-2a).
 */
export interface Confusable {
  /** The offending character as it appears in the input. */
  char: string;
  /** Its codepoint, e.g. `"U+0430"`. */
  codepoint: string;
  /** Human-readable description of what it is confusable with, e.g. `"a (U+0061)"`. */
  confusableWith: string;
  /** Which component it was found in. */
  component: ConfusableComponent;
  /** Zero-based index of the character within that component. */
  position: number;
}

/** Version stamps for every reproducibility-relevant data/algorithm source. */
export interface DataVersions {
  publicSuffixList: string;
  unicodeConfusables: string;
  unicodeScripts: string;
  idna: string;
  riskyTlds: string;
  brands: string;
  weights: string;
}

/**
 * Options accepted by `inspect()`.
 *
 * Beyond the inspection tuning knobs, this object configures the **policy
 * channel** — a separate, caller-owned set of allow/deny axes (TLD, host,
 * scheme, port, …) layered on top of the built-in deception analysis. Policy
 * hits surface in `reasons[]` with `layer: "policy"` and `weight: 0`, so they
 * are advisory only: they never change the deception `score` or `severity`.
 * When no policy field is set, inspection is byte-identical to passing no
 * options at all (no `policy` entry in `checksRun`, no policy reasons).
 *
 * Policy fields are flat and additive — each axis (H2–H4) contributes its own
 * optional field here; {@link InspectOptions} stays a single grouping.
 */
export interface InspectOptions {
  /**
   * Maximum number of recursive percent-decode passes. Bounded to keep
   * inspection total over adversarial input (no decode-bomb). Defaults to a
   * safe internal value.
   */
  maxDecodeDepth?: number;

  /**
   * Policy: TLD deny-list (default-allow). When set, a host whose TLD is in this
   * list emits the `tld_denied` policy reason. Everything else passes.
   *
   * Values are bare TLD labels (no leading dot) compared **case-insensitively**;
   * a leading dot is tolerated and stripped. The comparison is against the
   * **last label** of the host's public suffix (the TLD) — e.g. `co.uk` → `uk`.
   * IP / hostless inputs have no public suffix and never match.
   *
   * @example denyTlds: ["ru", "cn"]
   */
  denyTlds?: string[];

  /**
   * Policy: TLD allow-list (default-deny lockdown). When set, a host whose TLD is
   * **not** in this list emits the `tld_not_allowlisted` policy reason. Only the
   * listed TLDs pass.
   *
   * Values are bare TLD labels (no leading dot) compared **case-insensitively**;
   * a leading dot is tolerated and stripped. The comparison is against the
   * **last label** of the host's public suffix (the TLD). IP / hostless inputs
   * have no public suffix and never match.
   *
   * Precedence when both are set: the two axes are independent and either may
   * fire. A TLD on `denyTlds` emits `tld_denied`; the same input also emits
   * `tld_not_allowlisted` if `allowTlds` is set and the TLD is not in it.
   *
   * @example allowTlds: ["com", "de"]
   */
  allowTlds?: string[];

  /**
   * Policy: host deny-list (default-allow). When set, a host whose **registrable
   * domain** (eTLD+1) matches an entry emits the `host_denied` policy reason.
   * Everything else passes.
   *
   * Values are host names (no leading dot) compared **case-insensitively**; a
   * leading dot is tolerated and stripped. Matching is on the host's
   * **registrable domain**: an entry matches when, after stripping its own
   * leading public-suffix-agnostic dot and lower-casing, it equals the
   * registrable domain — so listing `example.com` matches `example.com` and
   * every subdomain (`sub.example.com`, both share registrable domain
   * `example.com`). Matching is at registrable-domain granularity: a bare
   * subdomain entry such as `sub.example.com` equals no registrable domain and
   * therefore matches nothing — list the registrable domain (`example.com`)
   * instead. IP / hostless inputs have no registrable domain and never match.
   *
   * @example denyHosts: ["evil.com", "phishy.io"]
   */
  denyHosts?: string[];

  /**
   * Policy: host allow-list (default-deny corporate lockdown — only company and
   * vendor domains pass). When set, a host whose **registrable domain** (eTLD+1)
   * is **not** matched by any entry emits the `host_not_allowlisted` policy
   * reason. Only the listed domains (and their subdomains) pass.
   *
   * Values are host names (no leading dot) compared **case-insensitively**; a
   * leading dot is tolerated and stripped. Matching is on the host's
   * **registrable domain**: listing `example.com` allows `example.com` and every
   * `*.example.com`. IP / hostless inputs have no registrable domain and never
   * match (so they never pass an allow-list).
   *
   * Precedence when both are set: the two axes are independent and either may
   * fire. A registrable domain on `denyHosts` emits `host_denied`; the same input
   * also emits `host_not_allowlisted` if `allowHosts` is set and the registrable
   * domain is not in it.
   *
   * @example allowHosts: ["mycompany.com", "vendor.io"]
   */
  allowHosts?: string[];

  /**
   * Policy: scheme allow-list (default-deny lockdown). When set, an input whose
   * scheme is **not** in this list emits the `scheme_denied` policy reason. Only
   * the listed schemes pass — e.g. `["https"]` for an https-only policy.
   *
   * Values are bare scheme names compared **case-insensitively**; a trailing (or
   * leading) colon is tolerated and stripped. The comparison is against the
   * input's parsed scheme. Opaque / hostless inputs still carry a scheme (e.g.
   * `javascript`, `data`), so scheme policy applies to them too. Inputs with **no
   * scheme** (`ctx.scheme === null`) are exempt — the scheme axis is skipped
   * entirely, so a schemeless input never emits `scheme_denied`.
   *
   * Distinct from the built-in `dangerous_scheme` deception detector: this is a
   * caller-owned policy channel (weight 0), not a scoring heuristic.
   *
   * Precedence when both scheme lists are set: the two are independent and both
   * map to the same `scheme_denied` code — the detail string distinguishes a
   * deny-list hit from a not-allow-listed one.
   *
   * @example allowSchemes: ["https"]
   */
  allowSchemes?: string[];

  /**
   * Policy: scheme deny-list (default-allow). When set, an input whose scheme is
   * in this list emits the `scheme_denied` policy reason. Everything else passes.
   *
   * Values are bare scheme names compared **case-insensitively**; a trailing (or
   * leading) colon is tolerated and stripped. The comparison is against the
   * input's parsed scheme. Opaque / hostless inputs still carry a scheme, so
   * `denySchemes: ["javascript", "data"]` matches them. Inputs with **no scheme**
   * are exempt (the scheme axis is skipped).
   *
   * Distinct from the built-in `dangerous_scheme` deception detector — advisory
   * only (weight 0), a separate channel.
   *
   * @example denySchemes: ["javascript", "data", "ftp"]
   */
  denySchemes?: string[];

  /**
   * Policy: port deny-list (default-allow). When set, an input with an
   * **explicit** port in this list emits the `port_denied` policy reason. Ports
   * are only evaluated when a port is explicitly present in the URL
   * (`ctx.port !== null`); inputs with no explicit port never emit a port
   * finding.
   *
   * @example denyPorts: [8080, 31337]
   */
  denyPorts?: number[];

  /**
   * Policy: deny non-standard ports (default-allow). When `true`, an input with
   * an **explicit** port that is not the standard default for its scheme emits
   * the `port_denied` policy reason — catching `:8080` / `:31337` phishing/exfil
   * ports without enumerating them.
   *
   * Standard defaults: `http`→80, `https`→443, `ftp`→21, `ws`→80, `wss`→443. A
   * port equal to its scheme's default is "standard"; any other explicit port —
   * or any explicit port on a scheme not in this map — is "non-standard". As with
   * `denyPorts`, only an explicit port (`ctx.port !== null`) is evaluated; inputs
   * with no explicit port never emit a port finding.
   *
   * When both `denyPorts` and `denyNonStandardPorts` flag the same port, at most
   * one `port_denied` is emitted (deduped) with a detail explaining why.
   *
   * @example denyNonStandardPorts: true
   */
  denyNonStandardPorts?: boolean;
}

/** The full inspection result. */
export interface InspectResult {
  schemaVersion: typeof SCHEMA_VERSION;
  status: Status;
  input: string;
  parsed: ParsedUrl | null;
  /** Risk score in [0,1], or `null` on invalid input. */
  score: number | null;
  severity: Severity | null;
  reasons: Reason[];
  confusables: Confusable[];
  checksRun: string[];
  checksSkipped: string[];
  dataVersions: DataVersions;
}
