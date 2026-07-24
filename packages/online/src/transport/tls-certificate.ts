/**
 * Certificate normalization for observational TLS inspection (LINK-fgdawgnj, M7a).
 *
 * Turns a raw {@link TlsHandshakeObservation} into a {@link NormalizedTlsObservation}
 * with three validation axes kept strictly independent:
 *
 * - trust: taken from the handshake's chain-trust signal;
 * - validity window: computed from the certificate's own notBefore/notAfter versus
 *   the observation instant, never from a socket verdict;
 * - hostname identity: computed with Node's standard identity checker
 *   ({@link X509Certificate.checkHost}), never inferred from the trust signal.
 *
 * All parsing is bounded (chain depth, per-certificate size) and any malformed or
 * oversized input surfaces as a typed {@link TlsCertificateAnalysisError}, which the
 * inspector maps to an `incomplete` outcome — never a safety claim.
 */

import { X509Certificate } from "node:crypto";

import { DerParseError, readCertificatePolicyOids } from "./tls-der.js";
import type {
  CertificateAssuranceLevel,
  NormalizedCertificate,
  NormalizedTlsObservation,
  TlsCertificateDefect,
  TlsHandshakeObservation,
  TlsInspectionPolicy,
} from "./tls-types.js";

export const DEFAULT_TLS_INSPECTION_POLICY: TlsInspectionPolicy = Object.freeze({
  maxTotalTimeMs: 10_000,
  maxChainDepth: 10,
  maxCertificateBytes: 65_536,
});

export function resolveTlsInspectionPolicy(
  policy: Partial<TlsInspectionPolicy> | undefined,
): TlsInspectionPolicy {
  const resolved: TlsInspectionPolicy = { ...DEFAULT_TLS_INSPECTION_POLICY, ...policy };
  requirePositiveInteger("maxTotalTimeMs", resolved.maxTotalTimeMs);
  requirePositiveInteger("maxChainDepth", resolved.maxChainDepth);
  requirePositiveInteger("maxCertificateBytes", resolved.maxCertificateBytes);
  if (resolved.maxTotalTimeMs > 2_147_483_647) {
    throw new RangeError("maxTotalTimeMs exceeds the runtime timer limit");
  }
  return Object.freeze(resolved);
}

export type TlsCertificateAnalysisCode =
  | "certificate-malformed"
  | "certificate-too-large"
  | "chain-too-deep";

/** A bounded-analysis failure while normalizing an observed certificate. */
export class TlsCertificateAnalysisError extends Error {
  constructor(readonly code: TlsCertificateAnalysisCode) {
    super(`tls certificate analysis failed: ${code}`);
    this.name = "TlsCertificateAnalysisError";
  }
}

/** CA/Browser Forum reserved certificate-policy OIDs, highest assurance first. */
const ASSURANCE_BY_OID: readonly (readonly [string, CertificateAssuranceLevel])[] = [
  ["2.23.140.1.1", "ev"],
  ["2.23.140.1.2.2", "ov"],
  ["2.23.140.1.2.3", "iv"],
  ["2.23.140.1.2.1", "dv"],
];

export interface NormalizeContext {
  readonly hostname: string;
  readonly observedAt: Date;
  readonly policy?: Partial<TlsInspectionPolicy>;
}

export function normalizeTlsCertificate(
  observation: TlsHandshakeObservation,
  context: NormalizeContext,
): NormalizedTlsObservation {
  const policy = resolveTlsInspectionPolicy(context.policy);
  const chain = observation.certificateChain;
  if (chain.length === 0) throw new TlsCertificateAnalysisError("certificate-malformed");
  if (chain.length > policy.maxChainDepth) throw new TlsCertificateAnalysisError("chain-too-deep");
  for (const certificate of chain) {
    if (certificate.byteLength > policy.maxCertificateBytes) {
      throw new TlsCertificateAnalysisError("certificate-too-large");
    }
  }

  const leafDer = chain[0]!;
  const leaf = parseLeaf(leafDer);
  const policyOids = readPolicyOids(leafDer);
  const subjectAltNames = parseDnsSans(leaf.subjectAltName);
  const notBeforeMs = leaf.validFromDate.getTime();
  const notAfterMs = leaf.validToDate.getTime();
  const observedMs = context.observedAt.getTime();

  const hostnameMatch = matchesHostname(leaf, context.hostname);
  const selfIssued = leaf.subject === leaf.issuer;
  const withinValidity = observedMs >= notBeforeMs && observedMs <= notAfterMs;

  const defects: TlsCertificateDefect[] = [];
  if (observedMs > notAfterMs) defects.push("expired");
  if (observedMs < notBeforeMs) defects.push("not-yet-valid");
  if (!hostnameMatch) defects.push("hostname-mismatch");
  if (!observation.chainTrusted) defects.push("untrusted");
  // `selfIssued` is a structural fact recorded on the leaf; it is only a defect
  // when the certificate is also untrusted (a self-signed cert not chaining to a
  // configured root). A self-issued leaf that nonetheless chains as trusted is not
  // flagged, which keeps `self-signed` a specific, non-redundant untrust reason.
  if (selfIssued && !observation.chainTrusted) defects.push("self-signed");

  const normalizedLeaf: NormalizedCertificate = {
    subject: leaf.subject,
    issuer: leaf.issuer,
    serialNumber: leaf.serialNumber,
    subjectAltNames,
    policyOids,
    assuranceLevel: assuranceFor(policyOids),
    notBefore: leaf.validFromDate.toISOString(),
    notAfter: leaf.validToDate.toISOString(),
    selfIssued,
  };

  return {
    serverName: observation.serverName,
    protocolVersion: observation.protocolVersion,
    leaf: normalizedLeaf,
    chainDepth: chain.length,
    validation: {
      chainTrusted: observation.chainTrusted,
      hostnameMatch,
      withinValidity,
      defects,
    },
  };
}

function parseLeaf(der: Uint8Array): X509Certificate {
  try {
    return new X509Certificate(Buffer.from(der));
  } catch {
    throw new TlsCertificateAnalysisError("certificate-malformed");
  }
}

function readPolicyOids(der: Uint8Array): readonly string[] {
  try {
    return readCertificatePolicyOids(der);
  } catch (error) {
    if (error instanceof DerParseError) throw new TlsCertificateAnalysisError("certificate-malformed");
    throw error;
  }
}

/** Standard identity match; ignores CN when SANs are present, per Node's checker. */
function matchesHostname(certificate: X509Certificate, hostname: string): boolean {
  if (hostname === "") return false;
  return certificate.checkHost(hostname) !== undefined;
}

function parseDnsSans(subjectAltName: string | undefined): readonly string[] {
  if (typeof subjectAltName !== "string" || subjectAltName === "") return [];
  return subjectAltName
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("DNS:"))
    .map((entry) => entry.slice(4));
}

function assuranceFor(policyOids: readonly string[]): CertificateAssuranceLevel {
  for (const [oid, level] of ASSURANCE_BY_OID) {
    if (policyOids.includes(oid)) return level;
  }
  return "unknown";
}

function requirePositiveInteger(name: keyof TlsInspectionPolicy, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
}
