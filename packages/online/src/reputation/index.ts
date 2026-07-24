/**
 * Source-attributed reputation adapters (Epic M).
 *
 * M1a ships the RDAP registration-age source client: IANA bootstrap routing, a
 * bounded domain lookup with read-through caching, and response normalization.
 * Age computation and the conjunctive finding (M1b) build on these primitives.
 */

export {
  parseRdapBootstrap,
  resolveRdapBase,
} from "./rdap-bootstrap.js";
export {
  DEFAULT_RDAP_MAX_REDIRECTS,
  fetchRdapDomain,
  RDAP_SOURCE_ID,
  RDAP_SOURCE_VERSION,
} from "./rdap-client.js";
export { normalizeRdapDomain } from "./rdap-normalize.js";
export { RDAP_SOURCE_DESCRIPTOR } from "./rdap-descriptor.js";
export {
  createRdapAgeEnricher,
  DEFAULT_YOUNG_DOMAIN_THRESHOLD_DAYS,
  RDAP_BRAND_CORROBORATION_CODES,
} from "./rdap-enricher.js";
export type { RdapAgeEnricherOptions } from "./rdap-enricher.js";
export {
  TLS_CERTIFICATE_EVIDENCE_TYPE,
  TLS_SOURCE_DESCRIPTOR,
  TLS_SOURCE_ID,
  TLS_SOURCE_VERSION,
} from "./tls-descriptor.js";
export { createTlsCertificateEnricher } from "./tls-enricher.js";
export type { TlsCertificateEnricherOptions } from "./tls-enricher.js";
export type {
  FetchRdapDomainOptions,
  RdapBootstrapRegistry,
  RdapCache,
  RdapCause,
  RdapCauseCode,
  RdapClock,
  RdapDomainRecord,
  RdapFetchResult,
  RdapHttpClient,
  RdapHttpRequest,
  RdapHttpResponse,
  RdapRouting,
} from "./types.js";
