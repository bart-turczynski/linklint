/**
 * Caller-owned BYOK secret wrapper (LINK-nlnyqofz, M2).
 *
 * The online-source contract requires that provider credentials never appear in
 * `InspectResult`, evidence payloads, errors, telemetry, cache keys, fixture
 * snapshots, or logs (see docs/online-runtime-boundary.md). A raw string cannot
 * enforce that: it serializes the moment it is spread into a payload or logged.
 *
 * {@link OnlineSecret} is an opaque holder whose ONLY reader is {@link
 * OnlineSecret.reveal}. Every incidental serialization path — `String(secret)`,
 * template interpolation, `JSON.stringify`, `console.log`/`util.inspect` — yields
 * a fixed redaction placeholder instead of the value. The value is held in a
 * closure, not an own property, so it is neither enumerable nor reachable through
 * `Object.values`, structured clone, or property inspection.
 */

/** Placeholder rendered by every non-`reveal` access path. */
export const REDACTED_SECRET = "[redacted OnlineSecret]" as const;

const SECRET_BRAND = Symbol.for("linklint.online.secret");

/**
 * A caller-owned credential that can be read exactly once per call site through
 * {@link reveal} and never leaks through incidental serialization.
 */
export interface OnlineSecret {
  readonly [SECRET_BRAND]: true;
  /**
   * Reveal the raw credential. This is the single auditable read path; adapters
   * call it only at the moment a value is placed into a provider authorization
   * header, never earlier and never into any other sink.
   */
  reveal(): string;
  /** Always the redaction placeholder — never the value. */
  toString(): string;
  /** Always the redaction placeholder — keeps secrets out of `JSON.stringify`. */
  toJSON(): string;
}

/**
 * Wrap a caller-owned credential. The value is copied into a closure and is not
 * retained as an own property, so the returned object exposes nothing to
 * enumeration, cloning, or serialization.
 *
 * @throws {TypeError} when `value` is not a non-empty string; a credential slot
 *   must be an explicit skip, never an empty or non-string secret.
 */
export function createOnlineSecret(value: string): OnlineSecret {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("createOnlineSecret requires a non-empty string value");
  }
  const held = value;
  const secret: OnlineSecret = {
    [SECRET_BRAND]: true,
    reveal(): string {
      return held;
    },
    toString(): string {
      return REDACTED_SECRET;
    },
    toJSON(): string {
      return REDACTED_SECRET;
    },
  };
  // Node's util.inspect (console.log) honors this hook; keep the value invisible.
  Object.defineProperty(secret, Symbol.for("nodejs.util.inspect.custom"), {
    value: () => REDACTED_SECRET,
    enumerable: false,
  });
  return Object.freeze(secret);
}

/** Runtime guard for a value produced by {@link createOnlineSecret}. */
export function isOnlineSecret(value: unknown): value is OnlineSecret {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { [SECRET_BRAND]?: unknown })[SECRET_BRAND] === true &&
    typeof (value as OnlineSecret).reveal === "function"
  );
}
