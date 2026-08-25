import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CERTIFICATE_ASSURANCE_LEVELS,
  isTlsObservationCauseCode,
  isTlsObservationOutcomeStatus,
  isTransportCauseCode,
  isTransportOutcomeStatus,
  TLS_CERTIFICATE_DEFECTS,
  TLS_OBSERVATION_CAUSE_CODES,
  TLS_OBSERVATION_OUTCOME_STATUSES,
  TRANSPORT_CAUSE_CODES,
  TRANSPORT_OUTCOME_STATUSES,
  TRANSPORT_SCHEMA_VERSION,
} from "../src/transport/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const repoRoot = join(packageRoot, "..", "..");

function src(...segments: string[]): string {
  return readFileSync(join(packageRoot, "src", ...segments), "utf8");
}

/** The quoted string members of a `type X = | "a" | "b";` alias. */
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

/** The quoted string members of a single function body. */
function functionMembers(source: string, name: string): string[] {
  const start = source.indexOf(`function ${name}(`);
  expect(start, `${name} is declared`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("\n}", start);
  return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((match) => match[1] as string);
}

// The transport outcome/cause registry is pinned to the TRANSPORT_SCHEMA_VERSION
// it registered under.
//
// This is the §6.4 pattern applied to a second value domain. The reason-code
// pin in `packages/core/test/docs-validation.test.ts` was proved to bite in both
// directions — RED on adding a code (LINK-mmelbkvv) and RED on removing one
// (LINK-eurtxkit) — and the same shape is used here: a checked-in sorted key set
// beside the stamp, asserting added/removed empty plus version equality. A prose
// grep was explicitly rejected as the weak guard for the reason-code domain and
// is no better here.
//
// The predecessor state, recorded because it is what this file replaced:
// `TransportCauseCode` (30 values) and `TlsObservationCauseCode` (18) were
// erased TypeScript unions with no runtime enumeration at all, and the only
// runtime code sets in the package were the module-private PARTIAL subsets
// `STABLE_OPERATION_CODES` (13 of 30) and `STABLE_OBSERVE_CODES` (7 of 18),
// which map an adapter's `error.code` and are not registries of the domain.
// Both subsets are still partial and are pinned as subsets below.
//
// Maintenance is one edit: on a real change to any of the six domains, move
// TRANSPORT_SCHEMA_VERSION and re-stamp both constants below in the same commit.
// A pin that may outlive its version is a pin that quietly stops checking.
describe("the transport outcome registry is pinned to TRANSPORT_SCHEMA_VERSION", () => {
  const PINNED_TRANSPORT_SCHEMA_VERSION = "1.0";

  /** Every registry key as of `PINNED_TRANSPORT_SCHEMA_VERSION`, sorted. */
  const PINNED: Readonly<Record<string, readonly string[]>> = {
    TRANSPORT_OUTCOME_STATUSES: ["blocked", "incomplete", "success"],
    TRANSPORT_CAUSE_CODES: [
      "authorization-required",
      "caller-aborted",
      "connect-error",
      "connect-refused",
      "connect-timeout",
      "connection-address-mismatch",
      "decompressed-response-too-large",
      "decompression-error",
      "dns-error",
      "dns-malformed",
      "dns-not-found",
      "dns-timeout",
      "hop-limit",
      "http-error",
      "http-malformed",
      "http-reset",
      "http-timeout",
      "invalid-url",
      "prohibited-address",
      "referer-not-same-origin",
      "response-headers-too-large",
      "response-too-large",
      "response-too-slow",
      "timeout",
      "tls-certificate",
      "tls-handshake",
      "unsupported-content-encoding",
      "unsupported-method",
      "unsupported-scheme",
      "url-credentials",
    ],
    TLS_OBSERVATION_OUTCOME_STATUSES: ["blocked", "incomplete", "observed"],
    TLS_OBSERVATION_CAUSE_CODES: [
      "caller-aborted",
      "certificate-malformed",
      "certificate-too-large",
      "chain-too-deep",
      "connect-error",
      "connect-refused",
      "connect-timeout",
      "connection-address-mismatch",
      "dns-error",
      "dns-malformed",
      "dns-not-found",
      "dns-timeout",
      "invalid-url",
      "prohibited-address",
      "timeout",
      "tls-handshake",
      "unsupported-scheme",
      "url-credentials",
    ],
    TLS_CERTIFICATE_DEFECTS: [
      "expired",
      "hostname-mismatch",
      "not-yet-valid",
      "self-signed",
      "untrusted",
    ],
    CERTIFICATE_ASSURANCE_LEVELS: ["dv", "ev", "iv", "ov", "unknown"],
  };

  const REGISTRY: Readonly<Record<string, readonly string[]>> = {
    TRANSPORT_OUTCOME_STATUSES,
    TRANSPORT_CAUSE_CODES,
    TLS_OBSERVATION_OUTCOME_STATUSES,
    TLS_OBSERVATION_CAUSE_CODES,
    TLS_CERTIFICATE_DEFECTS,
    CERTIFICATE_ASSURANCE_LEVELS,
  };

  const domains = Object.keys(PINNED);

  it("the pin covers every exported registry array and nothing else", () => {
    // Without this, adding a seventh domain to the registry and forgetting to
    // pin it would leave the new domain silently unguarded.
    expect(Object.keys(REGISTRY).sort()).toEqual(domains.slice().sort());
  });

  it.each(domains)("%s is pinned non-vacuously — non-empty, sorted, duplicate-free", (domain) => {
    // Without this, emptying an array would "fix" a failure by disabling the
    // guard, and an unsorted pin would fail for a reason that is not drift.
    const pinned = PINNED[domain] as readonly string[];
    expect(pinned.length).toBeGreaterThan(0);
    expect([...pinned]).toEqual([...pinned].sort());
    expect(new Set(pinned).size).toBe(pinned.length);
  });

  it("the pin is stamped with the CURRENT TRANSPORT_SCHEMA_VERSION", () => {
    expect(
      TRANSPORT_SCHEMA_VERSION,
      "TRANSPORT_SCHEMA_VERSION moved without re-stamping the registry pins " +
        "below it. Update PINNED_TRANSPORT_SCHEMA_VERSION and PINNED together, " +
        "in the commit that bumps the stamp (docs/architecture.md §6.4).",
    ).toBe(PINNED_TRANSPORT_SCHEMA_VERSION);
  });

  it.each(domains)("%s is exactly the set pinned to this stamp", (domain) => {
    const pinned = PINNED[domain] as readonly string[];
    const actual = REGISTRY[domain] as readonly string[];
    const added = actual.filter((value) => !pinned.includes(value));
    const removed = pinned.filter((value) => !actual.includes(value));

    expect(
      { added, removed },
      `${domain} is a CLOSED, publicly exported and publicly documented value ` +
        "domain, so this change owes a TRANSPORT_SCHEMA_VERSION bump " +
        "(docs/architecture.md §6.4). Bump it in " +
        "src/transport/outcome-registry.ts, then re-stamp both constants here.",
    ).toEqual({ added: [], removed: [] });
  });

  it.each(domains)("%s is exported sorted and frozen", (domain) => {
    const actual = REGISTRY[domain] as readonly string[];
    expect([...actual]).toEqual([...actual].sort());
    expect(Object.isFrozen(actual)).toBe(true);
  });
});

describe("the registry is the same set as the erased unions it enumerates", () => {
  // `ExhaustiveRegistry` in outcome-registry.ts already makes a drift between an
  // array and its union a COMPILE error. This is the same check at test time, so
  // a mutation to one side alone is red under `vitest` as well as under `tsc` —
  // a guard that only one of the two gates can see is half a guard.
  const transportTypes = src("transport", "types.ts");
  const tlsTypes = src("transport", "tls-types.ts");

  it.each([
    ["TransportCauseCode", transportTypes, TRANSPORT_CAUSE_CODES],
    ["TlsObservationCauseCode", tlsTypes, TLS_OBSERVATION_CAUSE_CODES],
    ["TlsCertificateDefect", tlsTypes, TLS_CERTIFICATE_DEFECTS],
    ["CertificateAssuranceLevel", tlsTypes, CERTIFICATE_ASSURANCE_LEVELS],
  ] as const)("%s and its registry array hold the same values", (alias, source, registry) => {
    expect([...unionMembers(source, alias)].sort()).toEqual([...registry].sort());
  });
});

describe("every hand-written transport cause list is a subset of the registry", () => {
  const safeTransport = src("transport", "safe-transport.ts");
  const tlsInspect = src("transport", "tls-inspect.ts");
  const tlsCertificate = src("transport", "tls-certificate.ts");
  const redirectChain = src("resolution", "redirect-chain.ts");

  it("STABLE_OPERATION_CODES is a PROPER subset used for adapter error mapping", () => {
    const stable = setMembers(safeTransport, "STABLE_OPERATION_CODES");
    expect(stable.filter((code) => !TRANSPORT_CAUSE_CODES.includes(code as never))).toEqual([]);
    // Proper, deliberately: the remaining codes are decided by the transport
    // itself and are not reportable by a port.
    expect(stable.length).toBeLessThan(TRANSPORT_CAUSE_CODES.length);
    expect(safeTransport).not.toContain("export const STABLE_OPERATION_CODES");
  });

  it("STABLE_OBSERVE_CODES is a PROPER subset under the same rule", () => {
    const stable = setMembers(tlsInspect, "STABLE_OBSERVE_CODES");
    expect(stable.filter((code) => !TLS_OBSERVATION_CAUSE_CODES.includes(code as never))).toEqual(
      [],
    );
    expect(stable.length).toBeLessThan(TLS_OBSERVATION_CAUSE_CODES.length);
    expect(tlsInspect).not.toContain("export const STABLE_OBSERVE_CODES");
  });

  it("TlsCertificateAnalysisCode is an alias over registry members, not a domain", () => {
    // It is excluded from the stamp on exactly this ground; if it ever grows a
    // value of its own, that ground disappears and this turns red.
    const analysis = unionMembers(tlsCertificate, "TlsCertificateAnalysisCode");
    expect(analysis.length).toBeGreaterThan(0);
    expect(analysis.filter((code) => !TLS_OBSERVATION_CAUSE_CODES.includes(code as never)))
      .toEqual([]);
  });

  it("retryableTransportCause branches only on registry members", () => {
    // `retryableTransportCause(code: string)` in redirect-chain.ts re-lists ten
    // transport cause codes by hand to decide `cause.retryable` on the
    // enrichment outcome. Typed `string`, it would answer `false` for a renamed
    // code with nothing red. This is the assertion that would catch that.
    const retryable = functionMembers(redirectChain, "retryableTransportCause");
    expect(retryable.length).toBeGreaterThan(0);
    expect(retryable.filter((code) => !TRANSPORT_CAUSE_CODES.includes(code as never))).toEqual([]);
  });
});

describe("docs/safe-transport.md publishes the registry it stamps", () => {
  // Closedness is decided by the DOCUMENTED registry, not the TypeScript
  // annotation (docs/architecture.md §6.4). Before this unit the doc named 6 of
  // the 30 transport cause codes and enumerated none of the six domains, so the
  // domains were undocumented rather than closed. These assertions are what
  // keeps the published enumeration and the exported one the same set.
  const doc = readFileSync(join(repoRoot, "docs", "safe-transport.md"), "utf8");
  const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

  it("states the current stamp", () => {
    expect(doc).toContain(`\`TRANSPORT_SCHEMA_VERSION\` is \`${TRANSPORT_SCHEMA_VERSION}\``);
    expect(readme).toContain(`(currently \`${TRANSPORT_SCHEMA_VERSION}\`)`);
  });

  it.each([
    ["TRANSPORT_CAUSE_CODES", TRANSPORT_CAUSE_CODES],
    ["TLS_OBSERVATION_CAUSE_CODES", TLS_OBSERVATION_CAUSE_CODES],
    ["TRANSPORT_OUTCOME_STATUSES", TRANSPORT_OUTCOME_STATUSES],
    ["TLS_OBSERVATION_OUTCOME_STATUSES", TLS_OBSERVATION_OUTCOME_STATUSES],
    ["TLS_CERTIFICATE_DEFECTS", TLS_CERTIFICATE_DEFECTS],
    ["CERTIFICATE_ASSURANCE_LEVELS", CERTIFICATE_ASSURANCE_LEVELS],
  ] as const)("names %s and every one of its members", (name, values) => {
    expect(doc).toContain(`\`${name}\``);
    const missing = values.filter((value) => !doc.includes(`\`${value}\``));
    expect(
      missing,
      `docs/safe-transport.md must enumerate every ${name} member; a value the ` +
        "doc does not publish is not a closed domain.",
    ).toEqual([]);
  });

  it("the fetch cause table has one row per TRANSPORT_CAUSE_CODES member", () => {
    const rows = [...doc.matchAll(/^\| `([a-z-]+)` \| `(blocked|incomplete)` \| /gm)].map(
      (match) => match[1] as string,
    );
    expect([...rows].sort()).toEqual([...TRANSPORT_CAUSE_CODES].sort());
  });
});

describe("the registry guards narrow an unknown value to its domain", () => {
  it("accepts every member and rejects non-members", () => {
    for (const code of TRANSPORT_CAUSE_CODES) expect(isTransportCauseCode(code)).toBe(true);
    for (const code of TLS_OBSERVATION_CAUSE_CODES) {
      expect(isTlsObservationCauseCode(code)).toBe(true);
    }
    for (const status of TRANSPORT_OUTCOME_STATUSES) {
      expect(isTransportOutcomeStatus(status)).toBe(true);
    }
    for (const status of TLS_OBSERVATION_OUTCOME_STATUSES) {
      expect(isTlsObservationOutcomeStatus(status)).toBe(true);
    }

    for (const value of ["ECONNRESET", "", "toString", 42, null, undefined, {}]) {
      expect(isTransportCauseCode(value)).toBe(false);
      expect(isTlsObservationCauseCode(value)).toBe(false);
      expect(isTransportOutcomeStatus(value)).toBe(false);
      expect(isTlsObservationOutcomeStatus(value)).toBe(false);
    }

    // The two cause domains are not the same set, and the guards are not
    // interchangeable.
    expect(isTlsObservationCauseCode("hop-limit")).toBe(false);
    expect(isTransportCauseCode("chain-too-deep")).toBe(false);
    expect(isTransportOutcomeStatus("observed")).toBe(false);
    expect(isTlsObservationOutcomeStatus("success")).toBe(false);
  });
});
