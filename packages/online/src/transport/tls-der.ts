/**
 * Minimal, bounded ASN.1 DER reader for the one field Node's high-level
 * certificate APIs do not expose: certificate-policy OIDs (LINK-fgdawgnj, M7a).
 *
 * `X509Certificate` surfaces subject, issuer, SANs, validity, and identity checks,
 * but not the `certificatePolicies` extension (OID 2.5.29.32) needed to tell DV
 * from OV/EV. This reader parses that extension directly from preserved DER. It is
 * intentionally strict — definite-length encoding only, every bound checked — and
 * throws {@link DerParseError} on any malformed or truncated input.
 */

const OID_CERTIFICATE_POLICIES = "2.5.29.32";
const CONTEXT_EXTENSIONS = 0xa3; // [3] EXPLICIT, tbsCertificate extensions
const TAG_SEQUENCE = 0x30;
const TAG_OID = 0x06;
const TAG_OCTET_STRING = 0x04;

/** A recoverable structural failure while reading DER; callers map it to a cause. */
export class DerParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerParseError";
  }
}

interface Tlv {
  readonly tag: number;
  readonly contentStart: number;
  readonly contentEnd: number;
}

function readTlv(bytes: Uint8Array, pos: number): Tlv {
  if (pos + 1 >= bytes.length) throw new DerParseError("truncated tag/length");
  const tag = bytes[pos]!;
  let cursor = pos + 1;
  let length = bytes[cursor++]!;
  if ((length & 0x80) !== 0) {
    const byteCount = length & 0x7f;
    if (byteCount === 0) throw new DerParseError("indefinite length is not allowed");
    if (byteCount > 4) throw new DerParseError("length field too large");
    if (cursor + byteCount > bytes.length) throw new DerParseError("truncated length");
    length = 0;
    for (let i = 0; i < byteCount; i++) length = length * 256 + bytes[cursor++]!;
  }
  const contentEnd = cursor + length;
  if (contentEnd > bytes.length) throw new DerParseError("content exceeds buffer");
  return { tag, contentStart: cursor, contentEnd };
}

/** Iterate the direct children of a constructed value's content range. */
function* childrenOf(bytes: Uint8Array, start: number, end: number): Generator<Tlv> {
  let pos = start;
  while (pos < end) {
    const tlv = readTlv(bytes, pos);
    yield tlv;
    pos = tlv.contentEnd;
  }
}

/** Decode an OBJECT IDENTIFIER body into dotted-decimal notation. */
function decodeOid(bytes: Uint8Array, start: number, end: number): string {
  if (end <= start) throw new DerParseError("empty OID");
  const arcs: number[] = [];
  let value = 0;
  let started = false;
  for (let i = start; i < end; i++) {
    const byte = bytes[i]!;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      if (!started) {
        arcs.push(Math.min(2, Math.floor(value / 40)));
        arcs.push(value - arcs[0]! * 40);
        started = true;
      } else {
        arcs.push(value);
      }
      value = 0;
    }
    if (value > Number.MAX_SAFE_INTEGER / 128) throw new DerParseError("OID arc overflow");
  }
  if (!started) throw new DerParseError("truncated OID");
  return arcs.join(".");
}

/**
 * Read the certificate-policy OIDs from a DER-encoded X.509 certificate. Returns an
 * empty array when the `certificatePolicies` extension is absent. Throws
 * {@link DerParseError} on malformed input.
 */
export function readCertificatePolicyOids(certificate: Uint8Array): readonly string[] {
  const outer = readTlv(certificate, 0);
  if (outer.tag !== TAG_SEQUENCE) throw new DerParseError("certificate is not a SEQUENCE");
  const tbs = childrenOf(certificate, outer.contentStart, outer.contentEnd).next().value;
  if (!tbs || tbs.tag !== TAG_SEQUENCE) throw new DerParseError("missing tbsCertificate");

  let extensions: Tlv | undefined;
  for (const field of childrenOf(certificate, tbs.contentStart, tbs.contentEnd)) {
    if (field.tag === CONTEXT_EXTENSIONS) {
      // [3] EXPLICIT wraps the extensions SEQUENCE.
      extensions = childrenOf(certificate, field.contentStart, field.contentEnd).next().value;
      break;
    }
  }
  if (!extensions || extensions.tag !== TAG_SEQUENCE) return [];

  for (const extension of childrenOf(certificate, extensions.contentStart, extensions.contentEnd)) {
    const parts = [...childrenOf(certificate, extension.contentStart, extension.contentEnd)];
    const idPart = parts[0];
    if (!idPart || idPart.tag !== TAG_OID) continue;
    if (decodeOid(certificate, idPart.contentStart, idPart.contentEnd) !== OID_CERTIFICATE_POLICIES) {
      continue;
    }
    const value = parts.at(-1);
    if (!value || value.tag !== TAG_OCTET_STRING) throw new DerParseError("malformed extnValue");
    const policySeq = childrenOf(certificate, value.contentStart, value.contentEnd).next().value;
    if (!policySeq || policySeq.tag !== TAG_SEQUENCE) throw new DerParseError("malformed policies");
    const oids: string[] = [];
    for (const info of childrenOf(certificate, policySeq.contentStart, policySeq.contentEnd)) {
      const idOid = childrenOf(certificate, info.contentStart, info.contentEnd).next().value;
      if (!idOid || idOid.tag !== TAG_OID) throw new DerParseError("malformed policyIdentifier");
      oids.push(decodeOid(certificate, idOid.contentStart, idOid.contentEnd));
    }
    return oids;
  }
  return [];
}
