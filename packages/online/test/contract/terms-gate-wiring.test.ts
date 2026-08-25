/**
 * PIN — the M2 terms "construction gate" as it actually stands (LINK-angnbelm).
 *
 * `docs/online-source-contract.md`, `docs/online-runtime-boundary.md` and
 * `docs/online-roadmap.md` all claim, in the present tense, that a source is
 * never constructed under terms it cannot honor. This file pins what the code
 * does TODAY so the gap is a measured fact rather than a reading:
 *
 * 1. the gate has NO non-test caller in the shipped tree;
 * 2. every one of the five reputation factories constructs with NO terms
 *    configuration at all — there is no seam for the gate to run in;
 * 3. the three doc claims exist, verbatim, as written.
 *
 * The next commit inverts (1) and (2). Until then, these assertions failing
 * means the wiring landed and this file is the thing that is out of date.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  createDnsStateEnricher,
  createRdapAgeEnricher,
  createTlsCertificateEnricher,
} from "../../src/reputation/index.js";
import {
  createPhishTankEnricher,
  createUrlhausEnricher,
} from "../../src/mirrors/index.js";
import type { DnsResolverPort } from "../../src/reputation/dns-types.js";
import type { RdapHttpClient } from "../../src/reputation/types.js";
import type { SafeTlsInspector } from "../../src/transport/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const repoRoot = join(packageRoot, "..", "..");

/** Prose ABOUT a symbol is the opposite of a call to it, so comments come out first. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

/** Every shipped `src` module outside `src/sources`, as `{path, code}` pairs. */
function shippedModulesOutsideSources(): readonly { path: string; code: string }[] {
  const srcDir = join(packageRoot, "src");
  return readdirSync(srcDir, { recursive: true, encoding: "utf8" })
    .filter((entry) => entry.endsWith(".ts"))
    .filter((entry) => !entry.startsWith("sources/") && !entry.startsWith("sources\\"))
    .map((entry) => ({
      path: entry,
      code: stripComments(readFileSync(join(srcDir, entry), "utf8")),
    }));
}

const noopRdapClient: RdapHttpClient = {
  request: () => Promise.reject(new Error("pin fixture: no RDAP request expected")),
};

const noopTlsInspector: SafeTlsInspector = {
  inspect: () => Promise.reject(new Error("pin fixture: no TLS inspection expected")),
};

const noopDnsResolver: DnsResolverPort = {
  query: () => Promise.reject(new Error("pin fixture: no DNS query expected")),
  validateDnssec: () => Promise.reject(new Error("pin fixture: no DNSSEC query expected")),
};

describe("PIN — the terms gate has no caller", () => {
  it("is never invoked by any shipped module outside src/sources", () => {
    const callers = shippedModulesOutsideSources().filter(
      ({ code }) =>
        code.includes("preflightOnlineSource(") || code.includes("assertValidSourceDescriptor("),
    );
    expect(callers.map(({ path }) => path)).toEqual([]);
  });

  it("has no factory option anywhere that names a commercial mode or attribution", () => {
    const naming = shippedModulesOutsideSources().filter(
      ({ code }) => code.includes("commercialMode") || code.includes("acceptAttribution"),
    );
    expect(naming.map(({ path }) => path)).toEqual([]);
  });
});

describe("PIN — every reputation factory constructs with no terms configuration", () => {
  it("createRdapAgeEnricher", () => {
    expect(createRdapAgeEnricher({ client: noopRdapClient, registry: null }).id).toBe(
      "rdap.registration-age",
    );
  });

  it("createTlsCertificateEnricher", () => {
    expect(createTlsCertificateEnricher({ inspector: noopTlsInspector }).id).toBe(
      "tls.live-endpoint",
    );
  });

  it("createDnsStateEnricher", () => {
    expect(createDnsStateEnricher({ resolver: noopDnsResolver }).id).toBe("dns.state");
  });

  it("createUrlhausEnricher — including under terms URLhaus does not grant", () => {
    // URLhaus supports non-commercial/fair-use only and requires attribution.
    // Today neither fact can be expressed at construction, let alone enforced.
    expect(createUrlhausEnricher({ resolveIndex: () => null }).id).toBe("urlhaus.mirror");
  });

  it("createPhishTankEnricher — including under terms PhishTank does not grant", () => {
    expect(createPhishTankEnricher({ resolveIndex: () => null }).id).toBe("phishtank.mirror");
  });
});

describe("PIN — the present-tense doc claims, verbatim", () => {
  const doc = (name: string): string => readFileSync(join(repoRoot, "docs", name), "utf8");

  it("online-source-contract.md calls terms a construction gate", () => {
    expect(doc("online-source-contract.md")).toContain(
      "**Terms are a construction gate.**",
    );
    expect(doc("online-source-contract.md")).toContain(
      "A source is never constructed under terms it cannot\n  honor, and never silently downgraded to a weaker default.",
    );
  });

  it("online-runtime-boundary.md calls terms an executable configuration gate", () => {
    expect(doc("online-runtime-boundary.md")).toContain(
      "terms are an executable configuration gate, not a documentation-only warning.",
    );
  });

  it("online-roadmap.md ships M2 including the construction gate", () => {
    expect(doc("online-roadmap.md")).toContain(
      "terms/attribution construction gate",
    );
  });
});
