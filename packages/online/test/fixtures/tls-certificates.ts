/**
 * Deterministic, checked-in DER certificate fixtures for TLS-inspection tests
 * (LINK-fgdawgnj, M7a). Generated once, offline, with OpenSSL; never minted at test
 * time. Each certificate is self-signed with a fixed validity window relative to the
 * fixture clock default (2026-01-01), an explicit SAN set, and — for `dvPolicy` — a
 * CA/Browser Forum DV certificate-policy OID (2.23.140.1.2.1). CI never performs a
 * live TLS handshake; the fixture observer replays these bytes.
 */

import type { TlsHandshakeObservation } from "../../src/transport/tls-types.js";

const BASE64: Readonly<Record<string, string>> = {
  // SAN example.com + www.example.com, valid 2020..2035.
  valid:
    "MIIBqTCCAVCgAwIBAgIUEotJcTZts+qKKb+yuV9Gsqb/bQwwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjAwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAQ13lQ5V9SRizlnRelqSmFK695skfU/5M9iEFsk5d6agQUYKxCaDZL/yRKZHP+Z0K15SP0Bc162REco47s/HqejfDB6MB0GA1UdDgQWBBSXuqOaeCydW/JqmAEVeZfi/Zyy/TAfBgNVHSMEGDAWgBSXuqOaeCydW/JqmAEVeZfi/Zyy/TAPBgNVHRMBAf8EBTADAQH/MCcGA1UdEQQgMB6CC2V4YW1wbGUuY29tgg93d3cuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgb+SWU9iWIPspsPXolkq+jUTSGb+TUzUZYbEvyOfPtwQCIFH0AscjSPtjwH0S73ey8qV7iyYpQ3e6sRQPJ3OBBHz7",
  // SAN example.com, expired 2018..2021.
  expired:
    "MIIBmjCCAT+gAwIBAgIUEodg3ACQ1S8zHAbDuD0RjKtlHMkwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMTgwMTAxMDAwMDAwWhcNMjEwMTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAIFPn2G+6Ovdo9uXd4nede2lEBFQqCaIFAWlLwjwAgNA1e/i6PTm9D3kcTjWSt6tctepARhitThX9Lp0Qak0QOjazBpMB0GA1UdDgQWBBQsw7bCZJ1m0pnkqjFhbnfq25toHzAfBgNVHSMEGDAWgBQsw7bCZJ1m0pnkqjFhbnfq25toHzAPBgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDKgqT6u6AKvT4ejzSNJEQQOn5WIzlH/z7w8qFPjrV2QQIhAPA48Ht4Q06J0Z2mQca1/ASu3QExxDVp48wTPuPaFfZd",
  // SAN example.com, not yet valid 2030..2035.
  notYetValid:
    "MIIBmTCCAT+gAwIBAgIUCJgZr2fJsVwA19D4LxlgUoXo6YowCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMzAwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG766qB+tqgavXmTDy8oAB6GrB4y12mgrRAcxXTppPB+fqHrT3O7VCzyVYAlHwTnqRBTsttPaPCbLQEtlzUrUNujazBpMB0GA1UdDgQWBBRknS7czmyf2qwSNlAyoU1dCmwE2DAfBgNVHSMEGDAWgBRknS7czmyf2qwSNlAyoU1dCmwE2DAPBgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIH9HvpGYyzR8QRqFd7/bMkJd97nBVQEJNDqhnoSYFjptAiEAl8AUl0qcq1DWpbpcA2LP+E9IUnpqTpcn4ZtmAHW6N2c=",
  // SAN other.example.net only — mismatches example.com.
  hostnameMismatch:
    "MIIBqjCCAVGgAwIBAgIUaKagIRzkQu3na2OOooJGeDxk2cwwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3RoZXIuZXhhbXBsZS5uZXQwHhcNMjAwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAcMRowGAYDVQQDDBFvdGhlci5leGFtcGxlLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOF1qaiCKQFvhjXk6ZgjWsMsBwSVfTqOIF/D0iY+ff8ZY/8FkwxFmEYK0o7byv0D2Y3Yg3G4IwQ7WWLhLUMuds+jcTBvMB0GA1UdDgQWBBRvjKT34g8y7J17GVM035HQX0enaDAfBgNVHSMEGDAWgBRvjKT34g8y7J17GVM035HQX0enaDAPBgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEW90aGVyLmV4YW1wbGUubmV0MAoGCCqGSM49BAMCA0cAMEQCIFFClO90lRiLFdzvY2CbxsYXzT6vwAo2EVps6qBAHY2uAiABSmYiUv4LakFi7fP/sg2WWR1ojk5Eq/a8/ernHcOhHQ==",
  // SAN example.com, self-issued with a distinctive subject/issuer CN.
  selfSigned:
    "MIIBsDCCAVegAwIBAgIUaiZmtM3jVGzTMJTBiExekr2tPWMwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXZXhhbXBsZS5jb20gU2VsZiBTaWduZWQwHhcNMjAwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAiMSAwHgYDVQQDDBdleGFtcGxlLmNvbSBTZWxmIFNpZ25lZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMlmaLjsTQ/3tUV+or6qebqVNYtLsrDO4JkH5tyTsaeuXQ6qzrpc1LPi/EhinGniSQ++IW6w7XW4mRDNP4MYv7qjazBpMB0GA1UdDgQWBBSZ3h8b0nXCTpRyGoVMMGiIJUvk3TAfBgNVHSMEGDAWgBSZ3h8b0nXCTpRyGoVMMGiIJUvk3TAPBgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0cAMEQCIE7JRvRZeg3hME8o+eR7pCa+xh+fr1zfFWad96roeVXFAiB2kOX5vMeV+cK/j/5XFd7npiqcTWNpFuDZ445WI8XPRQ==",
  // SAN *.example.com + example.com.
  wildcard:
    "MIIBrTCCAVKgAwIBAgIUD2t3DyEKMOCsQlFDB9zGcE8IjHgwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNKi5leGFtcGxlLmNvbTAeFw0yMDAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBgxFjAUBgNVBAMMDSouZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5mxMT9wIR6ro3+HQYJ57k21Tb0AAP7QkxbOQFTrycgvuK2fhYPePrWb2aNHMk4OLPKQQuarRg6yIZew/Ge/PKo3oweDAdBgNVHQ4EFgQUcn1ODL0p/llz0OsYsc2Tjgkasz4wHwYDVR0jBBgwFoAUcn1ODL0p/llz0OsYsc2Tjgkasz4wDwYDVR0TAQH/BAUwAwEB/zAlBgNVHREEHjAcgg0qLmV4YW1wbGUuY29tggtleGFtcGxlLmNvbTAKBggqhkjOPQQDAgNJADBGAiEAqmN0NEo8vkcTMcHLVuNSlrogzk+LkMPYzyGo1prJ3k4CIQDLAeLT2YaD6gVhEb7HNBnt0NYz1qaFuqwBJJAUXw+LpQ==",
  // SAN example.com, certificatePolicies=DV (2.23.140.1.2.1).
  dvPolicy:
    "MIIBrzCCAVWgAwIBAgIUX0Y3HkZAFXJr4jHtLGDTmkz7GjAwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjAwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEHVujrYbZKUAuYSZUasJHbbDJMBFvOuj1KmqSNmJLRRQa6sXCHEHO2TOcn7UlfTMn1Daotnfhyc6YZUiVu287KjgYAwfjAdBgNVHQ4EFgQUZYFknX/SWqzq4giKUdqcz5aTzsswHwYDVR0jBBgwFoAUZYFknX/SWqzq4giKUdqcz5aTzsswDwYDVR0TAQH/BAUwAwEB/zAWBgNVHREEDzANggtleGFtcGxlLmNvbTATBgNVHSAEDDAKMAgGBmeBDAECATAKBggqhkjOPQQDAgNIADBFAiBjq5TkJQYjx+I5cVeJCbDPV96ROUXl6UWVJWl9iaGjWAIhAOnzkllkeMBl7ydplndT5gjUGlJt82SrHGkyLTb1FZ0/",
};

export type TlsCertificateFixture = keyof typeof BASE64;

export function certificateDer(name: TlsCertificateFixture): Uint8Array {
  return new Uint8Array(Buffer.from(BASE64[name]!, "base64"));
}

export interface ObservationOverrides {
  readonly serverName?: string;
  readonly remoteAddress?: string;
  readonly remotePort?: number;
  readonly chainTrusted?: boolean;
  readonly trustErrorCode?: string | null;
  readonly protocolVersion?: string | null;
  readonly extraChain?: readonly TlsCertificateFixture[];
}

/** Build a raw handshake observation around a leaf fixture, with sane defaults. */
export function handshake(
  leaf: TlsCertificateFixture,
  overrides: ObservationOverrides = {},
): TlsHandshakeObservation {
  const chain = [certificateDer(leaf), ...(overrides.extraChain ?? []).map(certificateDer)];
  return {
    serverName: overrides.serverName ?? "example.com",
    remoteAddress: overrides.remoteAddress ?? "93.184.216.34",
    remotePort: overrides.remotePort ?? 443,
    certificateChain: chain,
    chainTrusted: overrides.chainTrusted ?? true,
    trustErrorCode:
      overrides.trustErrorCode !== undefined
        ? overrides.trustErrorCode
        : (overrides.chainTrusted ?? true)
          ? null
          : "SELF_SIGNED_CERT_IN_CHAIN",
    protocolVersion: overrides.protocolVersion !== undefined ? overrides.protocolVersion : "TLSv1.3",
  };
}
