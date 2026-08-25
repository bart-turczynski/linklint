import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as transport from "../src/transport/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const repoRoot = join(packageRoot, "..", "..");

function src(...segments: string[]): string {
  return readFileSync(join(packageRoot, "src", ...segments), "utf8");
}

/**
 * Extracts the quoted string members of a `type X = | "a" | "b";` alias.
 * A union that vanishes at runtime can only be counted from its source text —
 * which is precisely the state this file pins.
 */
function unionMembers(source: string, alias: string): string[] {
  const start = source.indexOf(`export type ${alias} =`);
  expect(start, `${alias} is declared`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(";", start);
  return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((match) => match[1] as string);
}

/** The quoted string members of a `new Set<...>([...])` initializer. */
function setMembers(source: string, name: string): string[] {
  const declared = source.indexOf(`const ${name} = new Set`);
  expect(declared, `${name} is declared`).toBeGreaterThanOrEqual(0);
  // Skip the generic argument — `new Set<TlsObservationCause["code"]>` quotes a
  // property name that is not a member.
  const start = source.indexOf("([", declared);
  const end = source.indexOf("]);", start);
  return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((match) => match[1] as string);
}

// LINK: transport outcome/cause schema stamp — BASELINE PIN.
//
// This file is committed BEFORE the registry exists, so the change it guards is
// visible as a diff rather than asserted after the fact. It records three facts
// about the transport outcome surface as it stands today:
//
//   1. `TransportCauseCode` and `TlsObservationCauseCode` are TypeScript unions
//      and nothing else. They are erased at runtime, so a consumer of
//      `@linklint/online/transport` cannot enumerate them, validate against
//      them, or detect that one moved.
//   2. The two runtime code sets that DO exist — `STABLE_OPERATION_CODES` and
//      `STABLE_OBSERVE_CODES` — are module-private, and each is a proper SUBSET
//      chosen for adapter error mapping. Neither is a registry of the domain.
//   3. No version stamp covers this surface. `ENRICHMENT_SCHEMA_VERSION` (core)
//      covers the structured enrichment report and explicitly disclaims
//      source-specific adapter cause codes; `SCHEMA_VERSION` (core) covers the
//      serialized `InspectResult`, which the transport outcome is not part of.
//
// The next commit replaces every assertion below with its mirror image.
describe("BASELINE: the transport outcome surface has no runtime registry", () => {
  const transportTypes = src("transport", "types.ts");
  const tlsTypes = src("transport", "tls-types.ts");
  const safeTransport = src("transport", "safe-transport.ts");
  const tlsInspect = src("transport", "tls-inspect.ts");

  const transportCauseCodes = unionMembers(transportTypes, "TransportCauseCode");
  const tlsObservationCauseCodes = unionMembers(tlsTypes, "TlsObservationCauseCode");

  it("the cause domains exist only as erased type aliases", () => {
    expect(transportCauseCodes).toHaveLength(30);
    expect(tlsObservationCauseCodes).toHaveLength(18);

    // Nothing on the public subpath enumerates either domain at runtime.
    const runtimeExports = Object.entries(transport)
      .filter(([, value]) => Array.isArray(value) || value instanceof Set)
      .map(([name]) => name);
    expect(runtimeExports).toEqual([]);
  });

  it("the only runtime code sets are module-private PARTIAL subsets", () => {
    const stableOperation = setMembers(safeTransport, "STABLE_OPERATION_CODES");
    const stableObserve = setMembers(tlsInspect, "STABLE_OBSERVE_CODES");

    // Private: not exported from their own module, let alone from the subpath.
    expect(safeTransport).not.toContain("export const STABLE_OPERATION_CODES");
    expect(tlsInspect).not.toContain("export const STABLE_OBSERVE_CODES");

    // Partial: 13 of 30 and 7 of 18. A subset used for mapping an adapter's
    // `error.code` is not an enumeration of the domain.
    expect(stableOperation).toHaveLength(13);
    expect(stableObserve).toHaveLength(7);
    expect(stableOperation.length).toBeLessThan(transportCauseCodes.length);
    expect(stableObserve.length).toBeLessThan(tlsObservationCauseCodes.length);
  });

  it("no version stamp covers the transport outcome surface", () => {
    expect(transport).not.toHaveProperty("TRANSPORT_SCHEMA_VERSION");
    expect(`${transportTypes}${tlsTypes}${safeTransport}${tlsInspect}`).not.toContain(
      "TRANSPORT_SCHEMA_VERSION",
    );
  });

  it("docs/safe-transport.md publishes the STATUSES but enumerates no cause domain", () => {
    const doc = readFileSync(join(repoRoot, "docs", "safe-transport.md"), "utf8");

    // The three outcome statuses are documented; the cause vocabulary is not.
    expect(doc).toContain("`SafeFetchOutcome.status` is one of");
    expect(doc).toContain("`TlsObservationOutcome.status` is `observed`, `blocked`, or `incomplete`");

    // Under docs/architecture.md §6.4 a domain is CLOSED when this repository
    // publishes an enumeration of its values. Only 6 of the 30 transport cause
    // codes are named anywhere in the doc, and never as a list — so today the
    // domain is undocumented rather than closed.
    const documented = transportCauseCodes.filter((code) => doc.includes(`\`${code}\``));
    expect(documented.length).toBeLessThan(transportCauseCodes.length);
    expect(documented).toEqual([
      "referer-not-same-origin",
      "response-too-slow",
      "response-headers-too-large",
      "timeout",
      "http-malformed",
      "http-error",
    ]);
  });
});
