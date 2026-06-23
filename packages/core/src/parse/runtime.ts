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
  /** Normalized policy configuration derived once per inspection. */
  policy: PolicyRuntimeConfig;
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
  return { maxDecodeDepth, idnPolicy, idnAllowlist, policy: normalizePolicyOptions(options) };
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

function normalizedList<T, U>(
  values: readonly T[] | undefined,
  normalize: (value: T) => U | null,
): PolicyList<U> {
  const normalized = (Array.isArray(values) ? values : [])
    .map(normalize)
    .filter((value): value is U => value !== null);
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
