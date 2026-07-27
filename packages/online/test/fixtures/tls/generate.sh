#!/usr/bin/env bash
# Regenerate the loopback TLS fixtures used by node-transport-live.test.ts.
#
# These are committed rather than generated at test time because Node has no
# built-in certificate signing API — node:crypto can make keypairs and parse
# X.509, but cannot issue a certificate. Shelling out to openssl during the
# suite would make the tests depend on a toolchain CI is not guaranteed to have.
#
# Everything here is a throwaway loopback identity. The keys are committed on
# purpose and secure nothing.
#
# Validity is deliberately ~100 years so the suite does not turn red one day for
# a reason that has nothing to do with the code. The one exception is the
# expired leaf, whose whole job is to be expired.
#
# Requires OpenSSL 3.2+ for -not_before / -not_after.
set -euo pipefail
cd "$(dirname "$0")"

DAYS=36500
SUBJ_CA="/CN=linklint test CA"

gen_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; }

# --- CA -------------------------------------------------------------------
gen_key ca.key.pem
openssl req -x509 -new -key ca.key.pem -sha256 -days "$DAYS" \
  -subj "$SUBJ_CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.cert.pem

# --- helper: sign a leaf with the CA --------------------------------------
# $1 out-prefix  $2 CN  $3 SAN  [$4 extra x509 flags]
sign_leaf() {
  local prefix="$1" cn="$2" san="$3"; shift 3
  gen_key "${prefix}.key.pem"
  openssl req -new -key "${prefix}.key.pem" -subj "/CN=${cn}" -out "${prefix}.csr"
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$san" > "${prefix}.ext"
  openssl x509 -req -in "${prefix}.csr" -CA ca.cert.pem -CAkey ca.key.pem \
    -CAcreateserial -sha256 -extfile "${prefix}.ext" "$@" -out "${prefix}.cert.pem"
  rm -f "${prefix}.csr" "${prefix}.ext"
}

# Valid leaf for the identity the tests connect as.
sign_leaf valid origin.example "DNS:origin.example" -days "$DAYS"

# Correctly signed and in-date, but for a different name — drives the
# checkServerIdentity re-check rather than chain verification.
sign_leaf wrong-name other.example "DNS:other.example" -days "$DAYS"

# Correctly signed and correctly named, but expired: CERT_HAS_EXPIRED.
sign_leaf expired origin.example "DNS:origin.example" \
  -not_before 20200101000000Z -not_after 20200102000000Z

# --- untrusted self-signed leaf (no CA in the chain) ----------------------
gen_key untrusted.key.pem
openssl req -x509 -new -key untrusted.key.pem -sha256 -days "$DAYS" \
  -subj "/CN=origin.example" -addext "subjectAltName=DNS:origin.example" \
  -out untrusted.cert.pem

rm -f ca.srl ca.cert.srl
echo "regenerated:"; ls -1 ./*.pem
