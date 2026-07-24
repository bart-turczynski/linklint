/**
 * IANA DNS bootstrap routing (LINK-okdrqxoz, M1a).
 *
 * The IANA RDAP bootstrap registry (RFC 9224) maps each TLD to one or more
 * authoritative RDAP base URLs. Routing is by the domain's final DNS label (the
 * TLD); a TLD absent from the registry is an explicit unsupported state, never a
 * guessed endpoint. HTTPS base URLs are preferred and always normalized to a
 * single trailing slash so the caller can append `domain/<name>` unambiguously.
 */

import type { RdapBootstrapRegistry, RdapRouting } from "./types.js";

/** Parse and validate an IANA bootstrap registry document. Returns `null` if malformed. */
export function parseRdapBootstrap(value: unknown): RdapBootstrapRegistry | null {
  if (!isRecord(value)) return null;
  if (typeof value.version !== "string" || typeof value.publication !== "string") return null;
  if (!Array.isArray(value.services)) return null;

  const services: [readonly string[], readonly string[]][] = [];
  for (const service of value.services) {
    if (!Array.isArray(service) || service.length !== 2) return null;
    const [tlds, urls] = service;
    if (!isStringArray(tlds) || !isStringArray(urls)) return null;
    services.push([tlds, urls]);
  }
  return { version: value.version, publication: value.publication, services };
}

/**
 * Route a registrable domain to an authoritative RDAP base URL. The domain is
 * expected to be an A-label; matching is case-insensitive on the TLD label.
 */
export function resolveRdapBase(
  registry: RdapBootstrapRegistry,
  registrableDomain: string,
): RdapRouting {
  const tld = tldLabel(registrableDomain);
  for (const [tlds, urls] of registry.services) {
    if (tlds.some((entry) => entry.toLowerCase() === tld)) {
      const base = preferHttpsBase(urls);
      if (base !== null) return { status: "routed", baseUrl: base, tld };
    }
  }
  return { status: "unsupported-tld", tld };
}

/** The final DNS label of a domain, lowercased (its TLD for bootstrap routing). */
function tldLabel(domain: string): string {
  const trimmed = domain.replace(/\.+$/, "").toLowerCase();
  const lastDot = trimmed.lastIndexOf(".");
  return lastDot === -1 ? trimmed : trimmed.slice(lastDot + 1);
}

/** Pick an HTTPS base URL when available, else the first URL; normalize the trailing slash. */
function preferHttpsBase(urls: readonly string[]): string | null {
  const https = urls.find((url) => url.toLowerCase().startsWith("https://"));
  const chosen = https ?? urls[0];
  if (chosen === undefined) return null;
  return chosen.endsWith("/") ? chosen : `${chosen}/`;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
