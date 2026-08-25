import type { InspectOptions } from "../schema/types.js";
import { DEFAULT_MAX_DECODE_DEPTH } from "./decode.js";
import { toUnicode } from "../unicode/idna.js";

/**
 * Per-inspection runtime configuration: the normalized, validated tuning knobs
 * derived once from {@link InspectOptions} and carried on the inspection
 * context. Keeps the raw caller-supplied options out of the hot path and ensures
 * inspection stays total (no throwing on nonsense values).
 */
export interface RuntimeConfig {
  /** Validated maximum number of recursive percent-decode passes. */
  maxDecodeDepth: number;
  /** IDN handling: `"block"` (default) flags non-ASCII registrable domains; `"allow"` exempts them. */
  idnPolicy: "block" | "allow";
  /** Normalized IDN allow-list: lower-cased, leading-dot-stripped registrable domains exempt under `"block"`. */
  idnAllowlist: ReadonlySet<string>;
  /**
   * Normalized caller false-positive suppression rules (default `[]`). Each rule
   * suppresses a reason `code`, optionally scoped to a registrable-domain `host`
   * (`null` = all hosts). See {@link import("../scoring/suppress.js").applySuppressions}.
   */
  suppressReasons: readonly SuppressionRule[];
  /** Normalized policy configuration derived once per inspection. */
  policy: PolicyRuntimeConfig;
}

/** A normalized suppression rule carried on the runtime config. */
export interface SuppressionRule {
  /** The reason code to suppress. */
  code: string;
  /**
   * Registrable-domain scope, Unicode-canonicalized + lower-cased (like an
   * `idnAllowlist` entry), or `null` to suppress `code` for all hosts.
   */
  host: string | null;
}

/** Normalized policy list: ordered for detail strings, indexed for matching. */
export interface PolicyList<T> {
  configured: boolean;
  values: readonly T[];
  set: ReadonlySet<T>;
}

/** Policy options normalized once before policy axes run. */
export interface PolicyRuntimeConfig {
  denyTlds: PolicyList<string>;
  allowTlds: PolicyList<string>;
  denyHosts: PolicyList<string>;
  allowHosts: PolicyList<string>;
  denySchemes: PolicyList<string>;
  allowSchemes: PolicyList<string>;
  denyPorts: PolicyList<number>;
  denyNonStandardPorts: boolean;
}

/**
 * Normalize caller {@link InspectOptions} into a {@link RuntimeConfig}. Defaults
 * `maxDecodeDepth` to {@link DEFAULT_MAX_DECODE_DEPTH} when unset, and falls back
 * to the default for any nonsense value (non-finite, negative, or non-integer).
 * Never throws — inspection must be total.
 */
export function normalizeOptions(options: InspectOptions): RuntimeConfig {
  const raw = options.maxDecodeDepth;
  const maxDecodeDepth =
    typeof raw === "number" && Number.isInteger(raw) && raw >= 0
      ? raw
      : DEFAULT_MAX_DECODE_DEPTH;
  // IDN handling defaults to "block"; any value other than the explicit "allow"
  // opt-out (including unset/nonsense) is treated as "block". Never throws.
  const idnPolicy = options.idnPolicy === "allow" ? "allow" : "block";
  // Canonicalize allow-list entries to their Unicode, lower-cased form so a
  // user's "münchen.de" matches a punycode (xn--) input and vice-versa.
  //
  // Routed through `normalizedList` — the same choke point the policy axes use —
  // rather than normalized inline. `idnAllowlist` is not a policy axis, which is
  // exactly why it missed the trim MR !41 (LINK-uxkrtcnw) placed there: the
  // choke point only protects what goes through it (LINK-qajalduf). Only the
  // membership set is kept; the ordered `values` and `configured` flag have no
  // reader here, because `idnAllowlist` has no allow-list-configured semantics
  // to report — an empty set simply exempts nothing.
  const idnAllowlist = normalizedList(options.idnAllowlist, normalizeIdnDomain).set;
  return {
    maxDecodeDepth,
    idnPolicy,
    idnAllowlist,
    suppressReasons: normalizeSuppressReasons(options.suppressReasons),
    policy: normalizePolicyOptions(options),
  };
}

/**
 * Normalize caller {@link InspectOptions.suppressReasons} into runtime rules.
 * Drops entries that are not objects or lack a string `code`. A `host` is
 * canonicalized to its Unicode, lower-cased, leading-dot-stripped registrable
 * form — mirroring `idnAllowlist` normalization so a rule's `host` matches an
 * input's registrable domain regardless of punycode/Unicode presentation. A
 * missing/blank/non-string `host` becomes `null` (suppress `code` for all hosts).
 * Never throws — inspection must be total.
 *
 * This is the one list-valued option that CANNOT route through
 * {@link normalizedList}: its entries are objects, not scalars, so there is no
 * single value for the list-level normalizer to trim — the caller's strings are
 * the `code` and `host` FIELDS one level down. It therefore calls
 * {@link trimListValue} directly on each of them, which is the same trim
 * `normalizedList` applies. Do not try to fold this into `normalizedList`; the
 * shapes do not match. Keep the two field trims here instead (LINK-qajalduf).
 */
export function normalizeSuppressReasons(
  rules: InspectOptions["suppressReasons"],
): readonly SuppressionRule[] {
  if (!Array.isArray(rules)) return [];
  const normalized: SuppressionRule[] = [];
  for (const rule of rules) {
    if (typeof rule !== "object" || rule === null) continue;
    const { code, host } = rule as { code?: unknown; host?: unknown };
    if (typeof code !== "string") continue;
    // Empty-after-trim DROPS the whole rule, matching normalizedList. A blank
    // `code` matches no reason today either, so this removes dead weight rather
    // than changing a verdict — and `suppressConfigured` reads the raw option,
    // never the normalized length, so the `suppression` honesty marker in
    // `checksRun` still appears.
    const normalizedCode = trimListValue(code);
    if (normalizedCode === "") continue;
    const trimmedHost = trimListValue(host);
    // A blank `host` still means "all hosts" — that is the documented shape of a
    // global rule, and it was already reached via `host.trim() !== ""` before
    // this. Only the VALUE was untrimmed. A host that canonicalizes to `""`
    // (e.g. a bare ".") stays a non-null dead scope that matches nothing; it
    // must NOT collapse to `null`, which would silently widen the rule to every
    // host.
    const normalizedHost =
      typeof trimmedHost === "string" && trimmedHost !== ""
        ? normalizeIdnDomain(trimmedHost)
        : null;
    normalized.push({ code: normalizedCode, host: normalizedHost });
  }
  return normalized;
}

export function normalizePolicyOptions(options: InspectOptions): PolicyRuntimeConfig {
  return {
    denyTlds: normalizedList(options.denyTlds, normalizeTld),
    allowTlds: normalizedList(options.allowTlds, normalizeTld),
    denyHosts: normalizedList(options.denyHosts, normalizeHost),
    allowHosts: normalizedList(options.allowHosts, normalizeHost),
    denySchemes: normalizedList(options.denySchemes, normalizeScheme),
    allowSchemes: normalizedList(options.allowSchemes, normalizeScheme),
    denyPorts: normalizedList(options.denyPorts, normalizePort),
    denyNonStandardPorts: options.denyNonStandardPorts === true,
  };
}

/**
 * The single trim applied to every caller-supplied list value. Non-strings pass
 * through untouched, so a numeric axis (`denyPorts`) is unaffected.
 *
 * Factored out of {@link normalizedList} so the one list-valued option whose
 * entries are OBJECTS — `suppressReasons` — can apply the identical trim to its
 * inner fields. Both callers must use this rather than an inline `.trim()`:
 * a second copy of the rule is a second thing to forget.
 */
function trimListValue<T>(value: T): T {
  return typeof value === "string" ? (value.trim() as unknown as T) : value;
}

/**
 * Normalize one list-valued option into its ordered values + membership set.
 *
 * Surrounding whitespace is stripped here, at the single choke point every
 * scalar list routes through, rather than in the per-axis normalizers — so a
 * future option inherits the trim by construction and cannot reintroduce the
 * fail-open by forgetting it. Building a list by splitting a config string
 * (`env.DENY_TLDS.split(",")`) is the natural way to configure policy, and an
 * untrimmed `" ru"` matches nothing while reporting nothing (LINK-uxkrtcnw).
 * The URL input is already trimmed on the way in; list values now get the same
 * courtesy.
 *
 * The seven policy axes and `idnAllowlist` all route through here.
 * `suppressReasons` is the sole exception and says why at its own definition.
 * Inheritance beats discipline: put a new list-valued option through this
 * function rather than normalizing it inline, which is precisely how
 * `idnAllowlist` missed the trim for a release (LINK-qajalduf).
 *
 * An entry that is EMPTY after normalization is DROPPED, not rejected:
 *
 * - `normalizeOptions` is contractually total ("Never throws — inspection must
 *   be total"), so the library cannot raise a usage error without breaking the
 *   invariant every caller is built on. The `UsageError` precedent belongs at
 *   the CLI boundary, where a human typed the flag and can be told; it stays
 *   there.
 * - Dropping is not a second fail-open. An empty string can never match any
 *   key this feeds — `publicSuffixTld`, `registrableDomainLower` and `scheme`
 *   are all non-empty wherever an axis runs, and `idn_host` compares against a
 *   registrable domain it has already guarded as non-empty — so `""` is already
 *   dead weight in the set today. Removing it changes no verdict, only the
 *   allow-list detail strings.
 * - On the allow-list axes it stays fail-CLOSED: `configured` is derived from
 *   `values !== undefined`, never from length, so `allowTlds: ["  "]` remains
 *   configured with an empty list and every input is reported as
 *   not-allow-listed. A fat-fingered allow-list gets loud, not silent.
 * - `idnAllowlist` is fail-CLOSED for a simpler reason: it is an exemption list,
 *   so an emptied one exempts nothing and every IDN keeps emitting `idn_host`.
 *   Dropping can only ever make it stricter, never more permissive.
 */
function normalizedList<T, U>(
  values: readonly T[] | undefined,
  normalize: (value: T) => U | null,
): PolicyList<U> {
  const normalized = (Array.isArray(values) ? values : [])
    .map(trimListValue)
    .map(normalize)
    .filter((value): value is U => value !== null && value !== ("" as unknown as U));
  return { configured: values !== undefined, values: normalized, set: new Set(normalized) };
}

/**
 * Canonicalize a registrable domain supplied by a caller — leading dot stripped,
 * Unicode (U-label) form, lower-cased — so it matches an input's registrable
 * domain regardless of punycode/Unicode presentation. Shared by `idnAllowlist`
 * and a `suppressReasons` rule's `host` so the two can never drift.
 */
function normalizeIdnDomain(value: string): string | null {
  return typeof value === "string" ? toUnicode(value.replace(/^\./, "")).toLowerCase() : null;
}

function normalizeTld(value: string): string | null {
  return typeof value === "string" ? value.replace(/^\./, "").toLowerCase() : null;
}

function normalizeHost(value: string): string | null {
  return typeof value === "string" ? value.replace(/^\./, "").toLowerCase() : null;
}

function normalizeScheme(value: string): string | null {
  return typeof value === "string" ? value.replace(/^:+|:+$/g, "").toLowerCase() : null;
}

function normalizePort(value: number): number | null {
  return typeof value === "number" ? value : null;
}
