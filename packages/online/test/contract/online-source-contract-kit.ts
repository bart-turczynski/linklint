/**
 * Shared online-source contract-test kit (LINK-nlnyqofz, M2).
 *
 * Every Epic M provider adapter's own test suite calls
 * {@link assertOnlineSourceContract} with its descriptor. The kit proves the
 * eight done-criteria that must hold for ANY compliant source — opt-in, missing
 * credentials, secret handling, freshness, disclosure capture, terms mode,
 * failure-to-check, and graceful `checksSkipped` — so a new adapter cannot ship
 * a subtly non-conforming contract. It is test-only infrastructure and is never
 * exported from the shipped package.
 */

import { expect } from "vitest";

import {
  assertValidSourceDescriptor,
  createOnlineSecret,
  freshnessFor,
  OnlineSourceConfigError,
  preflightOnlineSource,
  REDACTED_SECRET,
  type CommercialMode,
  type OnlineSourceConfig,
  type OnlineSourceDescriptor,
} from "../../src/sources/index.js";

export interface OnlineSourceContractOptions {
  /** A sample raw credential; required only when the descriptor demands a credential. */
  readonly sampleCredential?: string;
}

/** A commercial mode the descriptor does NOT support, for the terms-gate check. */
function unsupportedMode(descriptor: OnlineSourceDescriptor): CommercialMode | null {
  const all: readonly CommercialMode[] = ["non-commercial", "fair-use", "commercial"];
  return all.find((mode) => !descriptor.terms.supportedModes.includes(mode)) ?? null;
}

/** A minimally-satisfying config: supported mode, attribution accepted, consent granted, credential present. */
function satisfyingConfig(
  descriptor: OnlineSourceDescriptor,
  options: OnlineSourceContractOptions,
): OnlineSourceConfig {
  return {
    commercialMode: descriptor.terms.supportedModes[0]!,
    consent: { allow: [...descriptor.disclosure.consentRequired] },
    ...(descriptor.terms.attributionRequired ? { acceptAttribution: true } : {}),
    ...(descriptor.credentials.kind === "none"
      ? {}
      : { credential: createOnlineSecret(options.sampleCredential ?? "sample-credential") }),
  };
}

/** Copy a config with a single key removed (exactOptionalPropertyTypes-safe). */
function withoutKey(
  config: OnlineSourceConfig,
  key: "credential" | "consent",
): OnlineSourceConfig {
  const { [key]: _removed, ...rest } = config;
  return rest;
}

/**
 * Run the full contract battery against a descriptor. Throws (via `expect`) on
 * any violation, so a calling `it(...)` fails with the specific broken criterion.
 */
export function assertOnlineSourceContract(
  descriptor: OnlineSourceDescriptor,
  options: OnlineSourceContractOptions = {},
): void {
  // Descriptor shape is the precondition for every other guarantee.
  expect(() => assertValidSourceDescriptor(descriptor)).not.toThrow();

  if (descriptor.credentials.kind === "required" && options.sampleCredential === undefined) {
    throw new Error(
      `Contract kit for '${descriptor.id}' needs options.sampleCredential (credential is required)`,
    );
  }

  const base = satisfyingConfig(descriptor, options);

  // 1. Opt-in: a fully-satisfied config preflights to `ok` and does no I/O; the
  //    cleared disclosure set is exactly what the descriptor declared.
  const ready = preflightOnlineSource(descriptor, base);
  expect(ready.ok).toBe(true);
  if (ready.ok) {
    expect(ready.disclosure).toEqual(descriptor.disclosure.sends);
    if (descriptor.credentials.kind === "none") {
      expect(ready.credential).toBeNull();
    } else {
      expect(ready.credential).not.toBeNull();
    }
  }

  // 2. Missing credentials: a required-credential source with no secret skips
  //    with a machine-readable cause, never falling back to an anonymous call.
  if (descriptor.credentials.kind === "required") {
    const preflight = preflightOnlineSource(descriptor, withoutKey(base, "credential"));
    expect(preflight.ok).toBe(false);
    if (!preflight.ok) {
      expect(preflight.cause.code).toBe("credentials-missing");
      assertValidCause(preflight.cause);
    }
  }

  // 3. Secret handling: a BYOK secret never reveals through any serialization
  //    sink; only reveal() returns the value.
  if (descriptor.credentials.kind !== "none") {
    const raw = options.sampleCredential ?? "sample-credential";
    const secret = createOnlineSecret(raw);
    expect(secret.reveal()).toBe(raw);
    expect(String(secret)).toBe(REDACTED_SECRET);
    expect(`${secret}`).not.toContain(raw);
    expect(JSON.stringify({ credential: secret })).not.toContain(raw);
    expect(JSON.stringify(base)).not.toContain(raw);
  }

  // 4. Freshness: the source's declared capability governs emitted freshness.
  const observedAt = new Date("2026-07-24T00:00:00.000Z");
  const future = new Date("2026-07-24T01:00:00.000Z");
  const past = new Date("2026-07-23T23:00:00.000Z");
  if (descriptor.freshness.declaresExpiry) {
    expect(freshnessFor(descriptor.freshness, observedAt, future).status).toBe("fresh");
    const expired = freshnessFor(descriptor.freshness, observedAt, past);
    expect(expired.status).toBe(descriptor.freshness.staleWhenExpired ? "stale" : "fresh");
    expect(expired.expiresAt).toBe(past.toISOString());
  } else {
    const unknown = freshnessFor(descriptor.freshness, observedAt, future);
    expect(unknown.status).toBe("unknown");
    expect(unknown.expiresAt).toBeNull();
  }

  // 5. Disclosure capture: every consent-gated sent channel is declared, and
  //    an operation without that consent skips before disclosing anything.
  if (descriptor.disclosure.consentRequired.length > 0) {
    const preflight = preflightOnlineSource(descriptor, { ...base, consent: { allow: [] } });
    expect(preflight.ok).toBe(false);
    if (!preflight.ok) {
      expect(preflight.cause.code).toBe("disclosure-consent-required");
      assertValidCause(preflight.cause);
    }
  }

  // 6. Terms mode: an unsupported commercial mode is a construction error, and a
  //    required attribution not accepted is likewise refused up front.
  const badMode = unsupportedMode(descriptor);
  if (badMode !== null) {
    expect(() => preflightOnlineSource(descriptor, { ...base, commercialMode: badMode })).toThrow(
      OnlineSourceConfigError,
    );
  }
  if (descriptor.terms.attributionRequired) {
    expect(() =>
      preflightOnlineSource(descriptor, { ...base, acceptAttribution: false }),
    ).toThrow(OnlineSourceConfigError);
  }

  // 7 & 8. Failure-to-check and graceful checksSkipped: every runtime refusal is
  //    a valid EnrichmentCause (so it maps to `skipped`/`checksSkipped`), and the
  //    source never asserts safety — the honesty pin is fixed.
  expect(descriptor.noMatchSemantics).toBe("absence-is-not-safety");
  const anyRefusal =
    descriptor.credentials.kind === "required"
      ? preflightOnlineSource(descriptor, withoutKey(base, "credential"))
      : descriptor.disclosure.consentRequired.length > 0
        ? preflightOnlineSource(descriptor, { ...base, consent: { allow: [] } })
        : null;
  if (anyRefusal && !anyRefusal.ok) {
    assertValidCause(anyRefusal.cause);
  }
}

/** A structured skip cause must be machine-branchable and JSON-safe. */
function assertValidCause(cause: { code: string; message?: string; details?: unknown }): void {
  expect(typeof cause.code).toBe("string");
  expect(cause.code.length).toBeGreaterThan(0);
  expect(() => JSON.stringify(cause)).not.toThrow();
}
