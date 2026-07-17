import type { ReasonCode } from "./reason-codes.js";

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
 * Policy fields are flat and additive — each axis contributes its own
 * optional field here; {@link InspectOptions} stays a single grouping.
 */
/**
 * A single caller false-positive suppression rule (see
 * {@link InspectOptions.suppressReasons}). Suppresses a reason `code`, optionally
 * scoped to a registrable domain via `host`.
 */
export interface SuppressReasonRule {
  /** The reason code to suppress (any code linklint can emit). */
  code: ReasonCode;
  /**
   * Optional registrable-domain scope. When omitted, the rule suppresses `code`
   * for ALL hosts. When set, it applies only to inputs whose **registrable
   * domain** matches — compared like {@link InspectOptions.idnAllowlist}
   * (case-insensitive, Unicode-canonicalized, leading dot tolerated, covers all
   * subdomains). IP / hostless inputs have no registrable domain and never match
   * a host-scoped rule.
   */
  host?: string;
}

export interface InspectOptions {
  /**
   * Maximum number of recursive percent-decode passes. Bounded to keep
   * inspection total over adversarial input (no decode-bomb). Defaults to a
   * safe internal value.
   */
  maxDecodeDepth?: number;

  /**
   * Agent mode: enable the agent-gated detector channel (default `false`). These
   * are higher-false-positive heuristics aimed at LLM-agent / tool-use contexts.
   *
   * `agentMode` is an explicit, reproducible INPUT: the same `(url, options)`
   * always yields the same result. When `false` (or unset) the output is
   * byte-identical to passing no options — verdict AND bookkeeping (`checksRun`,
   * `checksSkipped`, `score`, `reasons`). When `true` and ≥1 agent-gated check
   * is evaluated, the `agent` channel token appears in `checksRun` (after
   * `lexical`/`policy`).
   *
   * Disabled agent-gated checks are not listed in `checksSkipped`.
   *
   * @example agentMode: true
   */
  agentMode?: boolean;

  /**
   * IDN handling (default `"block"`). A non-ASCII registrable domain emits the
   * scoring `idn_host` reason unless this is set to `"allow"` or the domain is
   * covered by `idnAllowlist`.
   *
   * Set `"allow"` for deployments that legitimately serve internationalized
   * domains (e.g. an Asian-market audience): IDNs are then not penalized and the
   * verdict is the historical, IDN-agnostic one. For granular control under
   * `"block"`, exempt specific domains with {@link idnAllowlist} instead.
   *
   * Unlike the policy axes below this is a scoring signal, not a weight-0
   * advisory channel. IP / hostless inputs and pure-ASCII hosts are never
   * affected.
   *
   * @example idnPolicy: "allow"
   */
  idnPolicy?: "block" | "allow";

  /**
   * IDN allow-list (only meaningful under `idnPolicy: "block"`). A non-ASCII
   * registrable domain whose value matches an entry does **not** emit `idn_host`
   * — the escape hatch for known-good internationalized domains while IDNs stay
   * blocked by default.
   *
   * Values are registrable domains compared **case-insensitively** against the
   * host's registrable domain (in its Unicode form); a leading dot is tolerated
   * and stripped. Listing the registrable domain covers all its subdomains.
   *
   * @example idnAllowlist: ["münchen.de", "日本語.jp"]
   */
  idnAllowlist?: string[];

  /**
   * Caller false-positive escape hatch — the general form of
   * {@link idnPolicy}/{@link idnAllowlist}, applied to EVERY heuristic. Each rule
   * marks a reason `code` a false positive; a matched reason STAYS in `reasons[]`
   * (annotated `suppressed: true`, never silently deleted) but its scoring weight
   * is zeroed, so `score`/`severity` drop as if the signal were absent. A
   * fully-suppressed set can lower the verdict to `severity: "info"` / `score: 0`.
   *
   * A rule with no `host` suppresses its `code` for all hosts; a rule with a
   * `host` applies only to inputs whose registrable domain matches (see
   * {@link SuppressReasonRule.host}). Rules with an unrecognized/invalid shape are
   * ignored (inspection is total, never throws).
   *
   * Honesty: whenever this field is present (even `[]`), the `suppression` token
   * appears in `checksRun`, so a result never hides that a caller escape hatch was
   * applied. When the field is absent, output is byte-for-byte unchanged.
   *
   * This is additive and backward-compatible — no `SCHEMA_VERSION` bump: the
   * `Reason.suppressed` marker is absent by default, so default-off callers see
   * exactly the pre-existing schema `1.1` output.
   *
   * @example suppressReasons: [{ code: "risky_tld" }, { code: "idn_host", host: "münchen.de" }]
   */
  suppressReasons?: SuppressReasonRule[];

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
