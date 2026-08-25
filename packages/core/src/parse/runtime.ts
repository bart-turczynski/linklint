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
  const idnAllowlist = new Set<string>(
    (Array.isArray(options.idnAllowlist) ? options.idnAllowlist : [])
      .filter((d): d is string => typeof d === "string")
      .map((d) => toUnicode(d.replace(/^\./, "")).toLowerCase()),
  );
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
    const normalizedHost =
      typeof host === "string" && host.trim() !== ""
        ? toUnicode(host.replace(/^\./, "")).toLowerCase()
        : null;
    normalized.push({ code, host: normalizedHost });
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
 * Normalize one policy axis into its ordered values + membership set.
 *
 * Surrounding whitespace is stripped here, at the single choke point every axis
 * routes through, rather than in the per-axis normalizers — so a future axis
 * inherits the trim by construction and cannot reintroduce the fail-open by
 * forgetting it. Building a list by splitting a config string
 * (`env.DENY_TLDS.split(",")`) is the natural way to configure policy, and an
 * untrimmed `" ru"` matches nothing while reporting nothing (LINK-uxkrtcnw).
 * The URL input is already trimmed on the way in; policy values now get the
 * same courtesy.
 *
 * An entry that is EMPTY after normalization is DROPPED, not rejected:
 *
 * - `normalizeOptions` is contractually total ("Never throws — inspection must
 *   be total"), so the library cannot raise a usage error without breaking the
 *   invariant every caller is built on. The `UsageError` precedent belongs at
 *   the CLI boundary, where a human typed the flag and can be told; it stays
 *   there.
 * - Dropping is not a second fail-open. An empty string can never match any
 *   axis key — `publicSuffixTld`, `registrableDomainLower` and `scheme` are all
 *   non-empty wherever an axis runs — so `""` is already dead weight in the set
 *   today. Removing it changes no verdict, only the allow-list detail strings.
 * - On the allow-list axes it stays fail-CLOSED: `configured` is derived from
 *   `values !== undefined`, never from length, so `allowTlds: ["  "]` remains
 *   configured with an empty list and every input is reported as
 *   not-allow-listed. A fat-fingered allow-list gets loud, not silent.
 */
function normalizedList<T, U>(
  values: readonly T[] | undefined,
  normalize: (value: T) => U | null,
): PolicyList<U> {
  const normalized = (Array.isArray(values) ? values : [])
    .map((value) => (typeof value === "string" ? (value.trim() as unknown as T) : value))
    .map(normalize)
    .filter((value): value is U => value !== null && value !== ("" as unknown as U));
  return { configured: values !== undefined, values: normalized, set: new Set(normalized) };
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
