/**
 * RDAP domain response normalization (LINK-okdrqxoz, M1a).
 *
 * Reduces a raw RDAP domain object to a flat, JSON-safe {@link RdapDomainRecord}.
 * Every field that is absent, malformed, or redacted becomes `null` (or an empty
 * list) — a missing registration date is unknown, never zero and never a young
 * or old assertion. RFC 9537 `redacted` entries are surfaced as their declared
 * names so downstream code can tell "unknown because redacted" from "unknown
 * because unsupported". Registrant country and parked-page detection are out of
 * scope per M1.
 */

import type { RdapDomainRecord } from "./types.js";

interface NormalizeContext {
  readonly domain: string;
  readonly observedAt: string;
  readonly expiresAt: string | null;
}

/** Normalize a parsed RDAP domain object. Non-object input yields an all-unknown record. */
export function normalizeRdapDomain(value: unknown, ctx: NormalizeContext): RdapDomainRecord {
  const root = isRecord(value) ? value : {};

  return {
    domain: ctx.domain,
    ldhName: asString(root.ldhName),
    unicodeName: asString(root.unicodeName),
    registrationDate: eventDate(root.events, "registration"),
    lastChangedDate: eventDate(root.events, "last changed"),
    expirationDate: eventDate(root.events, "expiration"),
    registrar: registrar(root.entities),
    nameservers: nameservers(root.nameservers),
    delegationSigned: delegationSigned(root.secureDNS),
    statuses: stringList(root.status),
    redacted: redactedNames(root.redacted),
    observedAt: ctx.observedAt,
    expiresAt: ctx.expiresAt,
  };
}

/** First `eventDate` for the given `eventAction`, normalized to ISO-8601, else `null`. */
function eventDate(events: unknown, action: string): string | null {
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    if (isRecord(event) && event.eventAction === action) {
      return isoInstant(event.eventDate);
    }
  }
  return null;
}

function registrar(entities: unknown): RdapDomainRecord["registrar"] {
  if (!Array.isArray(entities)) return null;
  for (const entity of entities) {
    if (!isRecord(entity)) continue;
    if (!stringList(entity.roles).includes("registrar")) continue;
    return { name: vcardFullName(entity.vcardArray), handle: asString(entity.handle) };
  }
  return null;
}

/** Extract the `fn` (formatted name) value from a jCard `vcardArray`. */
function vcardFullName(vcardArray: unknown): string | null {
  if (!Array.isArray(vcardArray) || vcardArray[1] === undefined) return null;
  const properties = vcardArray[1];
  if (!Array.isArray(properties)) return null;
  for (const property of properties) {
    if (Array.isArray(property) && property[0] === "fn") {
      return asString(property[3]);
    }
  }
  return null;
}

function nameservers(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names: string[] = [];
  for (const entry of value) {
    if (isRecord(entry)) {
      const name = asString(entry.ldhName) ?? asString(entry.unicodeName);
      if (name !== null) names.push(name);
    }
  }
  return names;
}

function delegationSigned(secureDNS: unknown): boolean | null {
  if (isRecord(secureDNS) && typeof secureDNS.delegationSigned === "boolean") {
    return secureDNS.delegationSigned;
  }
  return null;
}

function redactedNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names: string[] = [];
  for (const entry of value) {
    if (isRecord(entry) && isRecord(entry.name)) {
      const label = asString(entry.name.type) ?? asString(entry.name.description);
      if (label !== null) names.push(label);
    }
  }
  return names;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

/** Validate an RDAP date and re-emit it as a canonical ISO-8601 instant, else `null`. */
function isoInstant(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
