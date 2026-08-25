/**
 * The M2 terms gate, as wired (LINK-angnbelm).
 *
 * The previous commit pinned the defect: `preflightOnlineSource` and
 * `assertValidSourceDescriptor` had zero non-test callers, no factory accepted
 * terms, and three docs claimed in the present tense that a source is never
 * constructed under terms it cannot honor. Each assertion below is the
 * inversion of one of those pins.
 *
 * The cases come from {@link ONLINE_SOURCE_REGISTRY} and the accepted/refused
 * terms are DERIVED from each descriptor, so this gate follows a licence change
 * rather than restating one. Only URLhaus and PhishTank can refuse today —
 * RDAP/TLS/DNS grant all three commercial modes and require no attribution — and
 * the derivation makes that visible instead of assumed.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { OnlineSourceConfigError } from "../../src/sources/index.js";
import {
  acceptedTermsFor,
  ONLINE_SOURCE_REGISTRY,
  refusedTermsFor,
} from "./online-source-registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const repoRoot = join(packageRoot, "..", "..");

/** Prose ABOUT a symbol is the opposite of a call to it, so comments come out first. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

/** The shipped module that defines a factory, by the factory's own export name. */
const FACTORY_MODULES: Readonly<Record<string, string>> = {
  RDAP: "reputation/rdap-enricher.ts",
  TLS: "reputation/tls-enricher.ts",
  DNS: "reputation/dns-enricher.ts",
  URLhaus: "mirrors/urlhaus-enricher.ts",
  PhishTank: "mirrors/phishtank-enricher.ts",
};

function shippedModule(relative: string): string {
  return stripComments(readFileSync(join(packageRoot, "src", relative), "utf8"));
}

describe("terms gate — the construction seam exists", () => {
  it.each(ONLINE_SOURCE_REGISTRY)(
    "$name calls assertSourceTermsAccepted in its own module",
    ({ name }) => {
      const relative = FACTORY_MODULES[name];
      expect(relative, `no factory module mapped for '${name}'`).toBeDefined();
      expect(shippedModule(relative!)).toContain("assertSourceTermsAccepted(");
    },
  );

  it("the gate now has callers in the shipped tree outside src/sources", () => {
    const srcDir = join(packageRoot, "src");
    const callers = readdirSync(srcDir, { recursive: true, encoding: "utf8" })
      .filter((entry) => entry.endsWith(".ts"))
      .filter((entry) => !entry.startsWith("sources/") && !entry.startsWith("sources\\"))
      .filter((entry) =>
        stripComments(readFileSync(join(srcDir, entry), "utf8")).includes(
          "assertSourceTermsAccepted(",
        ),
      )
      .sort();

    expect(callers).toEqual(Object.values(FACTORY_MODULES).sort());
  });
});

describe("terms gate — a source constructs only under terms it can honor", () => {
  it.each(ONLINE_SOURCE_REGISTRY)(
    "$name constructs under the terms its licence grants",
    ({ descriptor, construct }) => {
      const enricher = construct(acceptedTermsFor(descriptor));
      expect(enricher.id).toBe(descriptor.id);
      expect(enricher.layer).toBe(descriptor.layer);
    },
  );

  it.each(ONLINE_SOURCE_REGISTRY)(
    "$name refuses construction under every terms value its licence withholds",
    ({ descriptor, construct }) => {
      const refusals = refusedTermsFor(descriptor);
      const grantsEverything =
        descriptor.terms.supportedModes.length === 3 && !descriptor.terms.attributionRequired;
      // A source whose terms grant everything has nothing to refuse. That is a
      // property of ITS DESCRIPTOR, not a hole in the gate — asserted rather
      // than skipped, so a later tightening shows up here.
      expect(refusals.length === 0).toBe(grantsEverything);

      for (const refusal of refusals) {
        let thrown: unknown;
        try {
          construct(refusal.terms);
        } catch (error) {
          thrown = error;
        }
        expect(thrown, `expected a refusal because ${refusal.why}`).toBeInstanceOf(
          OnlineSourceConfigError,
        );
        expect((thrown as OnlineSourceConfigError).code).toBe(refusal.code);
        expect((thrown as OnlineSourceConfigError).sourceId).toBe(descriptor.id);
      }
    },
  );

  /**
   * The two mirrors are the only sources that CAN refuse, so their refusals are
   * spelled out literally as well as derived: abuse.ch and PhishTank both grant
   * non-commercial / fair use with attribution and neither grants commercial use.
   */
  it("URLhaus and PhishTank refuse `commercial` and refuse a declined attribution", () => {
    const mirrors = ONLINE_SOURCE_REGISTRY.filter(
      (source) => source.descriptor.dataOrigin.kind === "caller-owned-mirror",
    );
    expect(mirrors.map((source) => source.name)).toEqual(["URLhaus", "PhishTank"]);

    for (const { construct, descriptor } of mirrors) {
      expect(() => construct({ commercialMode: "commercial", acceptAttribution: true })).toThrow(
        /does not support commercial mode 'commercial'/,
      );
      expect(() => construct({ commercialMode: "fair-use", acceptAttribution: false })).toThrow(
        /requires attribution/,
      );
      // …and the grant itself still works, so the refusal is not a blanket one.
      expect(construct({ commercialMode: "fair-use", acceptAttribution: true }).id).toBe(
        descriptor.id,
      );
    }
  });
});

describe("terms gate — construction asks for terms and nothing more", () => {
  /**
   * The mirror credential is revealed only in the UPDATERS. Querying a snapshot
   * the caller already owns must not demand the key that downloaded it, so the
   * construction gate stays terms-only: no `credential`, no `consent`.
   */
  it("no mirror enricher factory requires a credential or consent to construct", () => {
    for (const relative of ["mirrors/urlhaus-enricher.ts", "mirrors/phishtank-enricher.ts"]) {
      const code = shippedModule(relative);
      expect(code).not.toContain("credential");
      expect(code).not.toContain("OnlineSecret");
      expect(code).not.toContain("preflightOnlineSource(");
    }
  });

  it("keeps the runtime credential/disclosure seams out of every factory", () => {
    for (const relative of Object.values(FACTORY_MODULES)) {
      expect(shippedModule(relative)).not.toContain("preflightOnlineSource(");
    }
  });
});

describe("the present-tense doc claims are now true", () => {
  const doc = (name: string): string => readFileSync(join(repoRoot, "docs", name), "utf8");

  it("online-source-contract.md names the validator every factory calls", () => {
    const source = doc("online-source-contract.md");
    expect(source).toContain("**Terms are a construction gate.**");
    expect(source).toContain(
      "A source is never constructed under terms it cannot\n  honor, and never silently downgraded to a weaker default.",
    );
    expect(source).toContain("assertSourceTermsAccepted");
  });

  it("online-runtime-boundary.md still calls terms an executable configuration gate", () => {
    const source = doc("online-runtime-boundary.md");
    expect(source).toContain(
      "terms are an executable configuration gate, not a documentation-only warning.",
    );
    expect(source).toContain("assertSourceTermsAccepted");
  });

  it("online-roadmap.md ships M2 including the construction gate", () => {
    expect(doc("online-roadmap.md")).toContain("terms/attribution construction gate");
  });

  it("online-composition-root.md builds its worked example with terms", () => {
    const source = doc("online-composition-root.md");
    expect(source).toContain("commercialMode");
    // The worked root builds three enrichers; every one of them passes terms.
    const factories = source.match(/create(?:DnsState|TlsCertificate|RedirectChain)Enricher\(\{/g);
    expect(factories).not.toBeNull();
  });
});
