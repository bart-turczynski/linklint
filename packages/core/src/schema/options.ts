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
   * Additive and backward-compatible on the default path: the
   * `Reason.suppressed` marker is absent unless this option is present, so
   * default-off callers see exactly the pre-existing schema `1.1` output. That
   * is not a schema-stamp exemption — an optional field is still a serialized
   * field, and docs/architecture.md §6.4 puts serialized fields inside
   * SCHEMA_VERSION's ownership. This one entered the contract at `1.1` without
   * the bump it owed; CHANGELOG.md records the miss and does not retro-bump it.
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

/**
 * Every {@link InspectOptions} key, as a RUNTIME value.
 *
 * An interface has no runtime representation, so the intake below cannot ask
 * TypeScript what it knows — the list has to exist as data. Typing it
 * `Record<keyof InspectOptions, true>` makes the compiler enforce BOTH
 * directions on the literal: a key added to the interface and forgotten here is
 * a missing-property error, and a key here that the interface does not declare
 * is an excess-property error. The list therefore cannot drift from the
 * interface the way a hand-maintained array would.
 *
 * Mirrors how `policy/options.ts` derives POLICY_OPTION_KEYS from the axis
 * registry: the recognized-key set is never a free-standing literal that some
 * later edit can leave behind.
 */
const SYNC_OPTION_KEYS: Record<keyof InspectOptions, true> = {
  maxDecodeDepth: true,
  agentMode: true,
  idnPolicy: true,
  idnAllowlist: true,
  suppressReasons: true,
  denyTlds: true,
  allowTlds: true,
  denyHosts: true,
  allowHosts: true,
  allowSchemes: true,
  denySchemes: true,
  denyPorts: true,
  denyNonStandardPorts: true,
};

/**
 * The keys `InspectAsyncOptions` adds on top of {@link InspectOptions}.
 *
 * `inspectAsync` passes its whole superset options object straight through to
 * `inspect()`, so the synchronous intake must recognize these four or every
 * enriched call would report its own plumbing as dropped configuration. They
 * are listed here rather than imported from `inspect-async.ts` because a
 * runtime import in that direction would close an import cycle
 * (`inspect-async` → `inspect` → `schema/options`).
 *
 * Coverage against the real interface is asserted in
 * `test/option-intake.test.ts`, which parses both interface declarations and
 * fails if either grows a key this set does not carry.
 */
const ASYNC_ONLY_OPTION_KEYS = ["enrichers", "signal", "cache", "governor"] as const;

/** Every option key either entry point recognizes and actually applies. */
export const RECOGNIZED_OPTION_KEYS: ReadonlySet<string> = new Set<string>([
  ...Object.keys(SYNC_OPTION_KEYS),
  ...ASYNC_ONLY_OPTION_KEYS,
]);

/**
 * The `checksSkipped` token for an options ARGUMENT that was not a usable
 * object at all — `null`, a primitive, a function, or an object whose own keys
 * could not be enumerated. Nothing the caller configured could be read, so no
 * individual key can be named.
 *
 * Deliberately the bare-token counterpart of the per-key `options:<key>` form,
 * exactly as bare `policy` (the dispatcher itself failed, no axis verdict
 * exists) is the counterpart of `policy:<axis id>` — see docs/architecture.md
 * §5. As there, the two never appear together.
 */
export const UNUSABLE_OPTIONS_TOKEN = "options";

/** Namespace for the per-key form, matching `lexical:<id>` / `policy:<axis id>`. */
const OPTION_KEY_TOKEN_PREFIX = "options";

/**
 * Longest key echoed into a token. A key is caller-controlled text that ends up
 * in a serialized result, so it is bounded rather than trusted; the marker keeps
 * a truncated token visibly truncated.
 */
const MAX_ECHOED_KEY_LENGTH = 64;

/**
 * Characters kept verbatim in an echoed key. `checksSkipped` is a list of
 * `<namespace>:<id>` tokens that consumers split, join, and render (the cucumber
 * suite joins it on commas), so a key carrying a comma, a colon, a newline or a
 * control character is folded to `_` rather than allowed to forge a delimiter.
 * The substitution is lossy on purpose: the token names the mistake, it is not
 * a round-trip of it.
 */
const UNSAFE_KEY_CHARS = /[^A-Za-z0-9_$.-]/g;

/** The result of reading a caller's options argument. */
export interface OptionIntake {
  /**
   * The options to apply — the caller's own object, unchanged, or `{}` when the
   * argument was not a usable object. Never null, so every downstream reader
   * can dereference it.
   */
  readonly options: InspectOptions;
  /**
   * `checksSkipped` tokens naming configuration the caller supplied and did NOT
   * get. Empty for every well-formed call, so the default path is byte-for-byte
   * unchanged.
   */
  readonly skipped: readonly string[];
}

/** Shared empty options, so the unusable-argument path allocates nothing. */
const NO_OPTIONS: InspectOptions = Object.freeze({});

/**
 * Read a caller's options argument at the runtime boundary (LINK-sjsxfqoo).
 *
 * `inspect()` applies the keys it recognizes. Before this, it dropped every
 * other key in silence, so a mistyped `allowHost` produced a result
 * indistinguishable from one where no policy was ever requested — silent loss,
 * failing OPEN, in the one channel whose purpose is restriction. This makes the
 * loss REPORTED: each dropped key becomes an `options:<key>` entry in
 * `checksSkipped`, so a caller can tell the two cases apart from the result
 * alone, without a control run to diff against.
 *
 * Reporting rather than rejecting is forced by the never-throws guarantee (A1 /
 * LINK-zsbeqtcr): the rejection of an unknown key is an OUTCOME, never an
 * exception. It reuses `checksSkipped` — the channel that already exists to say
 * "this part of the verdict did not happen" — rather than minting a parallel
 * signal, and it reuses that channel's established `<namespace>:<id>` token
 * grammar rather than a new shape.
 *
 * The namespace is `options:`, not `policy:`. An unrecognized key is not
 * attributable to an axis (`maxDecodeDeph` is not a policy typo), and
 * `policy:<axis id>` is already pinned to the four axis ids by
 * docs/architecture.md §5 and `features/policy.feature`; overloading it with
 * arbitrary caller strings would break consumers that parse it.
 *
 * What counts as dropped:
 *
 *  - a key that is not recognized AND whose value is not `undefined`. An
 *    unrecognized key set to `undefined` configured nothing, so nothing was
 *    lost — this keeps the common `{ ...base, someKey: undefined }` spread
 *    silent, matching how `policyConfigured` already treats `undefined`.
 *  - a key whose value could not be read at all (a throwing getter). It was
 *    supplied and it was not applied, which is the same statement.
 *
 * Total by construction: key enumeration and every value read are guarded, so a
 * hostile options object is reported, never propagated. Output is deterministic
 * — keys are sorted, so two callers whose objects differ only in insertion
 * order get identical results, preserving the published determinism guarantee.
 */
export function intakeOptions(options: unknown): OptionIntake {
  // A function, a primitive, or null carries no readable configuration. Report
  // the argument itself and continue with defaults; before this, `null` — what
  // `JSON.parse('{"options":null}')` hands a plain-JS caller — dereferenced and
  // threw straight out of `inspect()`.
  if (typeof options !== "object" || options === null) {
    return { options: NO_OPTIONS, skipped: [UNUSABLE_OPTIONS_TOKEN] };
  }

  const source = options as Record<string, unknown>;
  let keys: string[];
  try {
    keys = Object.keys(source);
  } catch {
    // A Proxy may trap `ownKeys` and throw. Nothing can be named, so this is
    // the same statement as an unusable argument.
    return { options: NO_OPTIONS, skipped: [UNUSABLE_OPTIONS_TOKEN] };
  }

  const dropped: string[] = [];
  for (const key of keys) {
    if (RECOGNIZED_OPTION_KEYS.has(key)) continue;
    try {
      if (source[key] === undefined) continue;
    } catch {
      // An unreadable value is still configuration we did not apply. Fall
      // through and report it.
    }
    dropped.push(key);
  }

  if (dropped.length === 0) return { options: options as InspectOptions, skipped: [] };

  dropped.sort();
  // Distinct keys can collide after sanitizing/truncation; a token repeated in
  // `checksSkipped` says nothing extra, so collapse them.
  const skipped = [...new Set(dropped.map(optionKeyToken))];
  return { options: options as InspectOptions, skipped };
}

/** Render one dropped key as a bounded, delimiter-safe `checksSkipped` token. */
function optionKeyToken(key: string): string {
  const safe = key.replace(UNSAFE_KEY_CHARS, "_");
  const bounded =
    safe.length > MAX_ECHOED_KEY_LENGTH
      ? `${safe.slice(0, MAX_ECHOED_KEY_LENGTH)}_`
      : safe;
  return `${OPTION_KEY_TOKEN_PREFIX}:${bounded}`;
}

/**
 * The options argument as a usable object of type `T`, or `{}` when it is not
 * an object. The narrowing half of {@link intakeOptions}, for a caller that has
 * already routed the reporting half through `inspect()` — `inspectAsync` reads
 * its own four keys off the same argument and must not dereference `null`
 * either.
 */
export function usableOptions<T extends object>(options: unknown): T {
  return typeof options === "object" && options !== null ? (options as T) : ({} as T);
}
