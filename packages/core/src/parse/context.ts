import type { InspectionContext } from "../detectors/types.js";
import type { ParsedUrl } from "../schema/types.js";
import type { HostFacts } from "./host-facts.js";
import type { RawParts } from "./raw-parts.js";
import type { RuntimeConfig } from "./runtime.js";

/** Build the public `ParsedUrl` from raw parts and derived host facts. */
export function buildParsedUrl(raw: RawParts, facts: HostFacts): ParsedUrl {
  return {
    scheme: raw.scheme,
    userinfo: raw.userinfo,
    effectiveHost: facts.host === "" ? null : facts.host,
    registrableDomain: facts.psl.registrableDomain,
    publicSuffix: facts.psl.publicSuffix,
    subdomain: facts.psl.subdomain,
    hostLabels: facts.hostLabels,
    port: raw.port,
    path: raw.path,
    query: raw.query,
    fragment: raw.fragment,
    isIp: facts.psl.isIp,
  };
}

/** Build the internal detector `InspectionContext` from the parsed pieces. */
export function buildInspectionContext(
  input: string,
  raw: RawParts,
  facts: HostFacts,
  parsed: ParsedUrl,
  runtime: RuntimeConfig,
): InspectionContext {
  return {
    input,
    scheme: raw.scheme,
    userinfo: raw.userinfo,
    rawHost: raw.rawHost,
    host: facts.host,
    hostUnicode: facts.hostUnicode,
    isIp: facts.psl.isIp,
    hostLabels: facts.hostLabels,
    registrableDomain: facts.psl.registrableDomain,
    registrableDomainLower: facts.psl.registrableDomain?.toLowerCase() ?? null,
    publicSuffix: facts.psl.publicSuffix,
    publicSuffixTld: facts.psl.publicSuffix ? facts.psl.publicSuffix.split(".").pop()! : null,
    subdomain: facts.psl.subdomain,
    subdomainLabels: facts.psl.subdomain ? facts.psl.subdomain.split(".") : [],
    port: raw.port,
    path: raw.path,
    query: raw.query,
    fragment: raw.fragment,
    parsed,
    runtime,
  };
}
