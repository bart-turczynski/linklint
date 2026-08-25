/**
 * Runtime registry for the `@linklint/online/transport` outcome surface.
 *
 * `SafeFetchOutcome` and `TlsObservationOutcome` are what a caller of this
 * subpath branches on, and until this module the value domains they carry —
 * the outcome statuses, the two cause vocabularies, and the certificate
 * defect/assurance vocabularies — existed only as TypeScript unions. Those are
 * erased at build time, so a consumer could not enumerate them, check a
 * deserialized value against them, or tell that one had moved. The two runtime
 * sets that did exist (`STABLE_OPERATION_CODES` in `safe-transport.ts`,
 * `STABLE_OBSERVE_CODES` in `tls-inspect.ts`) are module-private proper subsets
 * used to map an adapter's `error.code`, not enumerations of the domain.
 *
 * ## What {@link TRANSPORT_SCHEMA_VERSION} owns
 *
 * The six arrays below, and the documented meaning of each of their members:
 * `SafeFetchOutcome.status`, `TransportCause.code`,
 * `TlsObservationOutcome.status`, `TlsObservationCause.code`,
 * `TlsCertificateValidation.defects`, and
 * `NormalizedCertificate.assuranceLevel`. Adding a value, removing one, or
 * changing what one means moves the stamp. `docs/safe-transport.md` publishes
 * the same six enumerations, which is what makes these domains CLOSED under
 * `docs/architecture.md` §6.4 — closedness is decided by the documented
 * registry, not by the TypeScript annotation.
 *
 * It does NOT own: `TransportAddressCategory` (the return of the
 * `classifyTransportAddress` classifier, not part of any outcome, and already
 * pinned by `test/address-table-consistency.test.ts`), `TransportProtocol` and
 * `TransportMethod` (request-side input domains), or `TlsCertificateAnalysisCode`
 * (an alias over three {@link TLS_OBSERVATION_CAUSE_CODES} members rather than a
 * domain of its own; the subset relation is pinned in
 * `test/transport-outcome-registry.test.ts`).
 *
 * ## Why a separate stamp rather than `ENRICHMENT_SCHEMA_VERSION`
 *
 * Core's `ENRICHMENT_SCHEMA_VERSION` owns the structured enrichment report and
 * its FRAMEWORK cause vocabulary; `schema/enrich.ts` states in as many words
 * that adapters may use their own source-specific `EnrichmentCause.code` values
 * and that the framework union covers only orchestration, cache, governor, and
 * provider-call boundary states. Transport cause codes reach an enrichment
 * report through exactly that adapter channel (`redirect-chain.ts` copies
 * `outcome.cause.code` verbatim), so folding them into the enrichment stamp
 * would widen a core-owned stamp to cover a vocabulary core disclaims and cannot
 * see. The dependency arrow also points the wrong way: `@linklint/online`
 * depends on `linklint`, so a change in this file cannot reach into
 * `packages/core` to move a version there. `SCHEMA_VERSION` is further still —
 * it owns the serialized `InspectResult`, which a transport outcome is not part
 * of.
 *
 * ## What reads it
 *
 * Honestly: no runtime code branches on {@link TRANSPORT_SCHEMA_VERSION}, and
 * this module deliberately ships no version-checking validator, because there is
 * no caller for one. It is a human- and consumer-facing declaration — the
 * channel a consumer pins against, in the same sense `SCHEMA_VERSION` is — and
 * its only reader inside this repository is the mechanical pin in
 * `test/transport-outcome-registry.test.ts`, which fails when a domain moves and
 * the stamp does not. The ARRAYS, by contrast, are load-bearing at runtime: the
 * type guards below back the adapter error mapping in `safe-transport.ts` and
 * `tls-inspect.ts`.
 */

import type {
  CertificateAssuranceLevel,
  TlsCertificateDefect,
  TlsObservationCauseCode,
  TlsObservationOutcome,
} from "./tls-types.js";
import type { SafeFetchOutcome, TransportCauseCode } from "./types.js";

/**
 * Version of the transport outcome surface enumerated in this module.
 *
 * Moves whenever one of the six arrays gains a value, loses one, or one of its
 * members changes documented meaning (`docs/architecture.md` §6.4). Re-stamp it
 * and the pinned key sets in `test/transport-outcome-registry.test.ts` in the
 * same commit.
 */
export const TRANSPORT_SCHEMA_VERSION = "1.0" as const;

/**
 * `readonly T[]` when `Values` enumerates the union `T` exactly, and an
 * unassignable marker naming the gap when it does not.
 *
 * This is what stops the runtime array and the erased union from drifting: a
 * union member left out of the array, or an array member that is not a union
 * member, is a compile error at the declaration below rather than a discrepancy
 * a reader has to notice. The unions stay declared in `types.ts` / `tls-types.ts`
 * so those modules remain type-only and importable without pulling in a runtime
 * module.
 */
type ExhaustiveRegistry<T extends string, Values extends readonly string[]> =
  [Exclude<T, Values[number]>] extends [never]
    ? [Exclude<Values[number], T>] extends [never]
      ? readonly T[]
      : { readonly NOT_A_MEMBER_OF_THE_UNION: Exclude<Values[number], T> }
    : { readonly MISSING_FROM_THE_REGISTRY: Exclude<T, Values[number]> };

const TRANSPORT_OUTCOME_STATUS_VALUES = ["blocked", "incomplete", "success"] as const;

const TRANSPORT_CAUSE_CODE_VALUES = [
  "authorization-required",
  "caller-aborted",
  "connect-error",
  "connect-refused",
  "connect-timeout",
  "connection-address-mismatch",
  "decompressed-response-too-large",
  "decompression-error",
  "dns-error",
  "dns-malformed",
  "dns-not-found",
  "dns-timeout",
  "hop-limit",
  "http-error",
  "http-malformed",
  "http-reset",
  "http-timeout",
  "invalid-url",
  "prohibited-address",
  "referer-not-same-origin",
  "response-headers-too-large",
  "response-too-large",
  "response-too-slow",
  "timeout",
  "tls-certificate",
  "tls-handshake",
  "unsupported-content-encoding",
  "unsupported-method",
  "unsupported-scheme",
  "url-credentials",
] as const;

const TLS_OBSERVATION_OUTCOME_STATUS_VALUES = ["blocked", "incomplete", "observed"] as const;

const TLS_OBSERVATION_CAUSE_CODE_VALUES = [
  "caller-aborted",
  "certificate-malformed",
  "certificate-too-large",
  "chain-too-deep",
  "connect-error",
  "connect-refused",
  "connect-timeout",
  "connection-address-mismatch",
  "dns-error",
  "dns-malformed",
  "dns-not-found",
  "dns-timeout",
  "invalid-url",
  "prohibited-address",
  "timeout",
  "tls-handshake",
  "unsupported-scheme",
  "url-credentials",
] as const;

const TLS_CERTIFICATE_DEFECT_VALUES = [
  "expired",
  "hostname-mismatch",
  "not-yet-valid",
  "self-signed",
  "untrusted",
] as const;

const CERTIFICATE_ASSURANCE_LEVEL_VALUES = ["dv", "ev", "iv", "ov", "unknown"] as const;

/** Every `SafeFetchOutcome.status`, sorted. */
export const TRANSPORT_OUTCOME_STATUSES: ExhaustiveRegistry<
  SafeFetchOutcome["status"],
  typeof TRANSPORT_OUTCOME_STATUS_VALUES
> = Object.freeze(TRANSPORT_OUTCOME_STATUS_VALUES);

/** Every `TransportCause.code` a `blocked` or `incomplete` fetch outcome can carry, sorted. */
export const TRANSPORT_CAUSE_CODES: ExhaustiveRegistry<
  TransportCauseCode,
  typeof TRANSPORT_CAUSE_CODE_VALUES
> = Object.freeze(TRANSPORT_CAUSE_CODE_VALUES);

/** Every `TlsObservationOutcome.status`, sorted. */
export const TLS_OBSERVATION_OUTCOME_STATUSES: ExhaustiveRegistry<
  TlsObservationOutcome["status"],
  typeof TLS_OBSERVATION_OUTCOME_STATUS_VALUES
> = Object.freeze(TLS_OBSERVATION_OUTCOME_STATUS_VALUES);

/** Every `TlsObservationCause.code`, sorted. */
export const TLS_OBSERVATION_CAUSE_CODES: ExhaustiveRegistry<
  TlsObservationCauseCode,
  typeof TLS_OBSERVATION_CAUSE_CODE_VALUES
> = Object.freeze(TLS_OBSERVATION_CAUSE_CODE_VALUES);

/**
 * Every `TlsCertificateValidation.defects` member, sorted. Several can hold at
 * once, so a consumer reads the whole set rather than the first entry.
 */
export const TLS_CERTIFICATE_DEFECTS: ExhaustiveRegistry<
  TlsCertificateDefect,
  typeof TLS_CERTIFICATE_DEFECT_VALUES
> = Object.freeze(TLS_CERTIFICATE_DEFECT_VALUES);

/** Every `NormalizedCertificate.assuranceLevel`, sorted. */
export const CERTIFICATE_ASSURANCE_LEVELS: ExhaustiveRegistry<
  CertificateAssuranceLevel,
  typeof CERTIFICATE_ASSURANCE_LEVEL_VALUES
> = Object.freeze(CERTIFICATE_ASSURANCE_LEVEL_VALUES);

const TRANSPORT_CAUSE_CODE_SET: ReadonlySet<string> = new Set(TRANSPORT_CAUSE_CODE_VALUES);
const TLS_OBSERVATION_CAUSE_CODE_SET: ReadonlySet<string> = new Set(
  TLS_OBSERVATION_CAUSE_CODE_VALUES,
);
const TRANSPORT_OUTCOME_STATUS_SET: ReadonlySet<string> = new Set(
  TRANSPORT_OUTCOME_STATUS_VALUES,
);
const TLS_OBSERVATION_OUTCOME_STATUS_SET: ReadonlySet<string> = new Set(
  TLS_OBSERVATION_OUTCOME_STATUS_VALUES,
);

/** Narrows an unknown value — a deserialized outcome, an adapter `error.code` — to the domain. */
export function isTransportCauseCode(value: unknown): value is TransportCauseCode {
  return typeof value === "string" && TRANSPORT_CAUSE_CODE_SET.has(value);
}

/** Narrows an unknown value to a `TlsObservationCause.code`. */
export function isTlsObservationCauseCode(value: unknown): value is TlsObservationCauseCode {
  return typeof value === "string" && TLS_OBSERVATION_CAUSE_CODE_SET.has(value);
}

/** Narrows an unknown value to a `SafeFetchOutcome.status`. */
export function isTransportOutcomeStatus(value: unknown): value is SafeFetchOutcome["status"] {
  return typeof value === "string" && TRANSPORT_OUTCOME_STATUS_SET.has(value);
}

/** Narrows an unknown value to a `TlsObservationOutcome.status`. */
export function isTlsObservationOutcomeStatus(
  value: unknown,
): value is TlsObservationOutcome["status"] {
  return typeof value === "string" && TLS_OBSERVATION_OUTCOME_STATUS_SET.has(value);
}
