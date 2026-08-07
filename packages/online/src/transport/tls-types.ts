/**
 * Types for the observational TLS-inspection capability (LINK-fgdawgnj, M7a).
 *
 * This is a strictly non-authoritative evidence path. A raw handshake is captured
 * with certificate validation DISABLED at the socket so that expired, not-yet-valid,
 * hostname-mismatched, and untrusted/self-signed certificates can be OBSERVED
 * instead of refused. Validity and identity are recomputed from the preserved DER and
 * are never inferred from the socket verdict; chain trust IS the socket verdict, and
 * is passed through without reinterpretation, because the verdict names at most one
 * fault and so cannot be decomposed (LINK-zgmixagu). A successful
 * observation NEVER implies that a normal L0 fetch to the same destination would be
 * permitted; observe sockets are captured, read, and discarded, never reused.
 */

/**
 * A raw, non-authoritative TLS handshake observation. Produced by a
 * {@link TlsObservationPort} after connecting to a pre-pinned address with the
 * original-host SNI and certificate validation disabled.
 */
export interface TlsHandshakeObservation {
  /** Original hostname presented for SNI and used for identity checks. */
  readonly serverName: string;
  /**
   * The peer address the socket OBSERVED, re-checked against the pinned
   * {@link TlsObserveConnectRequest.address}. A port that cannot observe it must
   * fail the observation rather than echo the requested value: the check compares
   * this field with the pin, so a substituted pin would confirm itself
   * (LINK-abozdqtp).
   */
  readonly remoteAddress: string;
  /** The peer port the socket OBSERVED, under the same rule as the address. */
  readonly remotePort: number;
  /** Leaf-first DER certificates the peer presented. */
  readonly certificateChain: readonly Uint8Array[];
  /**
   * The peer's chain-trust verdict against the caller's trust store, isolated from
   * hostname identity but NOT from the validity window — no verifier can isolate it,
   * because it reports one error at a time and a validity failure hides whatever else
   * is wrong with the chain (LINK-zgmixagu). Read `true` as "the chain verified" and
   * `false` as "trust was not established", not as "the chain is forged"; the
   * distinction lives in {@link trustErrorCode}. This is a trust signal, never an
   * identity claim.
   */
  readonly chainTrusted: boolean;
  /**
   * Peer authorization error code when the chain is not trusted, else `null`. It names
   * the fault the verifier stopped at, which may be one of several; a validity code
   * here does not mean the rest of the chain checked out.
   */
  readonly trustErrorCode: string | null;
  /** Negotiated protocol version string, e.g. `TLSv1.3`, when known. */
  readonly protocolVersion: string | null;
}

/** DV/OV/IV/EV posture derived from certificate-policy OIDs (CA/Browser Forum). */
export type CertificateAssuranceLevel = "dv" | "ov" | "iv" | "ev" | "unknown";

/** A normalized leaf certificate parsed from preserved DER. */
export interface NormalizedCertificate {
  readonly subject: string;
  readonly issuer: string;
  /** Uppercase hexadecimal serial number. */
  readonly serialNumber: string;
  /** DNS subject-alternative names, as presented. */
  readonly subjectAltNames: readonly string[];
  /** Certificate-policy OIDs parsed from DER; may be empty. */
  readonly policyOids: readonly string[];
  /** Assurance level inferred from `policyOids`; `unknown` when none is recognized. */
  readonly assuranceLevel: CertificateAssuranceLevel;
  /** ISO-8601 validity start. This is NOT reliable issuance age. */
  readonly notBefore: string;
  /** ISO-8601 validity end. */
  readonly notAfter: string;
  /** True when subject === issuer (structurally self-issued). Not a trust claim. */
  readonly selfIssued: boolean;
}

/**
 * A structured certificate/validation defect. Multiple defects can hold at once
 * (for example an expired self-signed certificate is both `expired` and
 * `self-signed`), so consumers must inspect the whole set. In particular `untrusted`
 * accompanies `expired` / `not-yet-valid` whenever the observation came from a real
 * verifier, which stops at the first fault and cannot certify the rest of the chain.
 */
export type TlsCertificateDefect =
  | "expired"
  | "not-yet-valid"
  | "hostname-mismatch"
  | "untrusted"
  | "self-signed";

/** Independently computed validation state for an observed leaf certificate. */
export interface TlsCertificateValidation {
  /**
   * Chain verification succeeded against a configured root, taken verbatim from the
   * handshake trust signal. `false` means trust was not established — see the
   * observation's `trustErrorCode` for the fault the verifier stopped at.
   */
  readonly chainTrusted: boolean;
  /** Original-host identity match, computed via the standard Node identity checker. */
  readonly hostnameMatch: boolean;
  /** Observation instant lies within `[notBefore, notAfter]`. */
  readonly withinValidity: boolean;
  /** Every detected defect; empty when trusted, current, and identity-matched. */
  readonly defects: readonly TlsCertificateDefect[];
}

/** The normalized, non-authoritative result of inspecting a peer's certificate. */
export interface NormalizedTlsObservation {
  readonly serverName: string;
  readonly protocolVersion: string | null;
  readonly leaf: NormalizedCertificate;
  /** Count of presented certificates (leaf plus any intermediates). */
  readonly chainDepth: number;
  readonly validation: TlsCertificateValidation;
}

/** Bounds on TLS-inspection work. Rejected configuration keeps the safe defaults. */
export interface TlsInspectionPolicy {
  /** Total wall-clock budget for one inspection, including handshake and parsing. */
  readonly maxTotalTimeMs: number;
  /** Maximum presented certificates parsed; a deeper chain is a typed failure. */
  readonly maxChainDepth: number;
  /** Maximum bytes for any single presented certificate. */
  readonly maxCertificateBytes: number;
}

/** A pinned, classified connection target for a single TLS observation. */
export interface TlsObserveConnectRequest {
  readonly hostname: string;
  readonly address: string;
  readonly port: number;
  /** Original-host SNI/identity; always the inspected hostname. */
  readonly serverName: string;
  readonly signal?: AbortSignal;
}

/**
 * The connection primitive for observational TLS. It is deliberately separate from
 * the fetch {@link ConnectorPort} so an observe socket can never be handed to the
 * HTTP layer.
 */
export interface TlsObservationPort {
  observe(request: TlsObserveConnectRequest): Promise<TlsHandshakeObservation>;
}

export type TlsObservationCauseCode =
  | "invalid-url"
  | "unsupported-scheme"
  | "url-credentials"
  | "prohibited-address"
  | "dns-not-found"
  | "dns-timeout"
  | "dns-malformed"
  | "dns-error"
  | "connect-refused"
  | "connect-timeout"
  | "connect-error"
  | "connection-address-mismatch"
  | "tls-handshake"
  | "certificate-malformed"
  | "certificate-too-large"
  | "chain-too-deep"
  | "timeout"
  | "caller-aborted";

export interface TlsObservationCause {
  readonly code: TlsObservationCauseCode;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/** Server-visible attempt evidence for one TLS inspection. */
export interface TlsObservationEvidence {
  readonly type: "tls.attempt";
  readonly subject: { readonly kind: "url"; readonly value: string };
  readonly observedAt: string;
  readonly protocol?: "https:";
  readonly hostname?: string;
  readonly port?: number;
  /**
   * The addresses the resolver returned for this hop — for the built-in resolver, one
   * `dns.lookup(hostname, { all: true, verbatim: true })`, not an authoritative A/AAAA
   * RRset. `selectedAddress` is always one of these (`LINK-rbghrpru`).
   */
  readonly resolvedAddresses?: readonly string[];
  readonly selectedAddress?: string;
}

interface TlsObservationOutcomeBase {
  readonly subject: { readonly kind: "url"; readonly value: string };
  readonly observedAt: string;
  readonly evidence: TlsObservationEvidence;
}

/**
 * A completed observation. NON-AUTHORITATIVE: it records what the peer presented
 * and how it validates, and never implies a normal fetch would be allowed.
 */
export interface TlsObserved extends TlsObservationOutcomeBase {
  readonly status: "observed";
  readonly observation: NormalizedTlsObservation;
}

/** Reserved for transport-policy refusal (a prohibited pinned address). */
export interface TlsObservationBlocked extends TlsObservationOutcomeBase {
  readonly status: "blocked";
  readonly cause: TlsObservationCause;
}

/** DNS, connection, handshake, certificate-analysis, timeout, or cancellation. */
export interface TlsObservationIncomplete extends TlsObservationOutcomeBase {
  readonly status: "incomplete";
  readonly cause: TlsObservationCause;
}

export type TlsObservationOutcome =
  | TlsObserved
  | TlsObservationBlocked
  | TlsObservationIncomplete;

export interface TlsInspectRequest {
  readonly url: string;
  readonly signal?: AbortSignal;
}

export interface SafeTlsInspector {
  inspect(request: TlsInspectRequest): Promise<TlsObservationOutcome>;
}
