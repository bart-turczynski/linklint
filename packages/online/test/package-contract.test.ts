import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as mirrors from "../src/mirrors/index.js";
import * as online from "../src/index.js";
import * as reputation from "../src/reputation/index.js";
import * as resolution from "../src/resolution/index.js";
import * as transport from "../src/transport/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const repoRoot = join(packageRoot, "..", "..");

/** Every shipped `src/mirrors` module, concatenated, for source-fact assertions. */
function mirrorSources(only?: (name: string) => boolean): string {
  const mirrorsDir = join(packageRoot, "src", "mirrors");
  return readdirSync(mirrorsDir)
    .filter((name) => name.endsWith(".ts"))
    .filter((name) => only?.(name) ?? true)
    .map((name) => readFileSync(join(mirrorsDir, name), "utf8"))
    .join("\n");
}

/** Drop comments: prose ABOUT a forbidden token is the opposite of using one. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

describe("@linklint/online package boundary", () => {
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
    dependencies: Record<string, string>;
    engines: { node: string };
    exports: Record<string, unknown>;
  };

  it("is Node 24+, depends one-way on core, and exposes no browser condition", () => {
    expect(manifest.engines.node).toBe(">=24");
    expect(manifest.dependencies).toEqual({ linklint: "workspace:*" });
    expect(JSON.stringify(manifest.exports)).not.toContain('"browser"');
  });

  it("exposes the source contract at the root and keeps fixtures internal", () => {
    // The root owns public source metadata, consent, and BYOK contract (M2).
    expect(online.preflightOnlineSource).toBeTypeOf("function");
    expect(online.assertValidSourceDescriptor).toBeTypeOf("function");
    expect(online.createOnlineSecret).toBeTypeOf("function");
    expect(online.OnlineSourceConfigError).toBeTypeOf("function");
    expect(manifest.exports).not.toHaveProperty("./testing");
    expect(manifest.exports).toHaveProperty("./transport");
    expect(manifest.exports).toHaveProperty("./resolution");
    expect(manifest.exports).toHaveProperty("./reputation");
    expect(manifest.exports).toHaveProperty("./mirrors");
    expect(transport.createSafeTransport).toBeTypeOf("function");
    expect(transport.createNodeSafeTransport).toBeTypeOf("function");
    expect(transport.classifyTransportAddress).toBeTypeOf("function");
    // M7a: observational TLS inspection over the same safe pinned transport.
    expect(transport.createSafeTlsInspector).toBeTypeOf("function");
    expect(transport.createNodeSafeTlsInspector).toBeTypeOf("function");
    expect(transport.normalizeTlsCertificate).toBeTypeOf("function");
    expect(transport.readCertificatePolicyOids).toBeTypeOf("function");
    expect(transport.DEFAULT_TLS_INSPECTION_POLICY).toBeTypeOf("object");
    const transportExport = manifest.exports["./transport"] as Record<string, string>;
    expect(Object.keys(transportExport)).toEqual(["types", "default"]);
    expect(resolution.decodeEmbeddedWrapper).toBeTypeOf("function");
    expect(resolution.createEmbeddedWrapperEnricher).toBeTypeOf("function");
    expect(resolution.createRedirectChainEnricher).toBeTypeOf("function");
    const resolutionExport = manifest.exports["./resolution"] as Record<string, string>;
    expect(Object.keys(resolutionExport)).toEqual(["types", "default"]);
    expect(reputation.fetchRdapDomain).toBeTypeOf("function");
    expect(reputation.resolveRdapBase).toBeTypeOf("function");
    // LINK-mkddydzr: every other capability ships a Node factory; RDAP now does
    // too, so `fetchRdapDomain`'s injected client contract is actually runnable.
    expect(reputation.createNodeRdapHttpClient).toBeTypeOf("function");
    // LINK-mkddydzr sub-unit B: the bootstrap registry is now acquirable rather
    // than something every caller had to obtain and freshness-check by hand.
    expect(reputation.updateRdapBootstrap).toBeTypeOf("function");
    expect(reputation.IANA_RDAP_BOOTSTRAP_URL).toBe("https://data.iana.org/rdap/dns.json");
    expect(reputation.RDAP_SOURCE_DESCRIPTOR).toBeTypeOf("object");
    // M7b: live TLS certificate evidence enricher.
    expect(reputation.createTlsCertificateEnricher).toBeTypeOf("function");
    expect(reputation.TLS_SOURCE_DESCRIPTOR).toBeTypeOf("object");
    expect(reputation.TLS_CERTIFICATE_EVIDENCE_TYPE).toBe("tls.certificate");
    // M9a1: DNS record state evidence enricher.
    expect(reputation.createDnsStateEnricher).toBeTypeOf("function");
    expect(reputation.DNS_SOURCE_DESCRIPTOR).toBeTypeOf("object");
    expect(reputation.DNS_RECORDS_EVIDENCE_TYPE).toBe("dns.records");
    expect(reputation.DNS_DNSSEC_EVIDENCE_TYPE).toBe("dns.dnssec");
    const reputationExport = manifest.exports["./reputation"] as Record<string, string>;
    expect(Object.keys(reputationExport)).toEqual(["types", "default"]);
    expect(mirrors.updateUrlhausSnapshot).toBeTypeOf("function");
    expect(mirrors.parseUrlhausCsv).toBeTypeOf("function");
    expect(mirrors.createUrlhausIndex).toBeTypeOf("function");
    expect(mirrors.createUrlhausEnricher).toBeTypeOf("function");
    expect(mirrors.canonicalizeUrl).toBeTypeOf("function");
    expect(mirrors.URLHAUS_SOURCE_DESCRIPTOR).toBeTypeOf("object");
    expect(mirrors.updatePhishTankSnapshot).toBeTypeOf("function");
    expect(mirrors.parsePhishTankCsv).toBeTypeOf("function");
    expect(mirrors.createPhishTankIndex).toBeTypeOf("function");
    expect(mirrors.createPhishTankEnricher).toBeTypeOf("function");
    expect(mirrors.PHISHTANK_SOURCE_DESCRIPTOR).toBeTypeOf("object");
    const mirrorsExport = manifest.exports["./mirrors"] as Record<string, string>;
    expect(Object.keys(mirrorsExport)).toEqual(["types", "default"]);
  });

  it("does not grant online authority to the existing CLI or MCP packages", () => {
    for (const name of ["cli", "mcp"]) {
      const adapterManifest = readFileSync(
        join(repoRoot, "packages", name, "package.json"),
        "utf8",
      );
      expect(adapterManifest).not.toContain("@linklint/online");
    }
  });

  it("implements fixture ports without concrete DNS, socket, TLS, HTTP, or fetch calls", () => {
    const testingDir = join(packageRoot, "src", "testing");
    const source = readdirSync(testingDir)
      .filter((name) => name.endsWith(".ts"))
      .map((name) => readFileSync(join(testingDir, name), "utf8"))
      .join("\n");

    expect(source).not.toMatch(/from\s+["']node:(?:dns|net|tls|http|https)["']/);
    expect(source).not.toMatch(/\bfetch\s*\(/);
  });

  it("keeps local wrapper decoding free of network clients and vendor decoder calls", () => {
    const resolutionDir = join(packageRoot, "src", "resolution");
    const source = readFileSync(join(resolutionDir, "embedded-wrapper.ts"), "utf8");

    expect(source).not.toMatch(/from\s+["']node:(?:dns|net|tls|http|https)["']/);
    expect(source).not.toMatch(/\bfetch\s*\(/);
    expect(source).not.toContain("tap-api-v2.proofpoint.com/v2/url/decode");
  });

  /**
   * The RDAP client is the one concrete network client that deliberately sits
   * OUTSIDE L0 (a registry is a provider, not an inspected destination). The
   * two properties that keep that safe are pinned here as source facts: it
   * borrows L0's address table rather than declaring a second one, and it has
   * no credential or ambient-configuration surface at all.
   */
  it("keeps the RDAP provider client credential-free, ambient-free, and on the shared address policy", () => {
    const source = readFileSync(join(packageRoot, "src", "reputation", "rdap-node.ts"), "utf8");
    // Comments are stripped first: the file explains at length that it reads no
    // ambient configuration and sends no credential, and a prose mention of
    // `process.env` is the opposite of the thing being forbidden.
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

    expect(code).not.toContain("process.env");
    expect(code).not.toMatch(/["']authorization["']/i);
    expect(code).not.toMatch(/["']cookie["']/i);
    expect(source).toContain("classifyTransportAddress");
    // A second classifier, rather than a reuse of the shared table, would show
    // up as this package's block-list primitive appearing here.
    expect(code).not.toContain("BlockList");
  });

  /**
   * LINK-mkddydzr sub-unit B. The IANA bootstrap registry is provider data the
   * caller downloads and owns. `docs/online-runtime-boundary.md` forbids
   * bundling a feed snapshot in the npm artifact, and the easiest way to break
   * that is to check in a `dns.json` "for convenience" and quietly read it as a
   * fallback. Neither the shipped tree nor the acquisition module may contain
   * one.
   */
  it("ships no bundled IANA bootstrap document and no filesystem store", () => {
    const srcDir = join(packageRoot, "src");
    const jsonInSrc = readdirSync(srcDir, { recursive: true, encoding: "utf8" }).filter((entry) =>
      entry.endsWith(".json"),
    );
    expect(jsonInSrc).toEqual([]);

    const updater = readFileSync(
      join(packageRoot, "src", "reputation", "rdap-bootstrap-updater.ts"),
      "utf8",
    );
    const code = updater.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // The caller owns the directory or database; this module ships the store
    // interface and reaches for no filesystem of its own.
    expect(code).not.toMatch(/from\s+["']node:(?:fs|fs\/promises|path|os)["']/);
    expect(code).not.toContain("process.env");
    // No credential slot exists to reveal into.
    expect(code).not.toContain("credential");
    expect(code).not.toMatch(/["']authorization["']/i);
  });

  /**
   * LINK-mpkglaqb. `updateUrlhausSnapshot` and `updatePhishTankSnapshot` were
   * shipped and tested but both took an injected `*HttpClient` the package did
   * not supply, so no caller could refresh a mirror with anything
   * `@linklint/online` provided. Both feeds now ship a `createNode*` factory
   * behind their port, matching every other capability.
   */
  it("ships a Node HTTP client for each mirror feed", () => {
    expect(mirrors.createNodeUrlhausHttpClient).toBeTypeOf("function");
    expect(mirrors.createNodePhishTankHttpClient).toBeTypeOf("function");
    expect(mirrors.UrlhausHttpFailure).toBeTypeOf("function");
    expect(mirrors.PhishTankHttpFailure).toBeTypeOf("function");
    // Side-effect-free construction: a factory call opens no socket and reads
    // no configuration, so importing the subpath still performs no I/O.
    expect(mirrors.createNodeUrlhausHttpClient().request).toBeTypeOf("function");
    expect(mirrors.createNodePhishTankHttpClient().request).toBeTypeOf("function");
  });

  /**
   * LINK-mpkglaqb, the other half of the acceptance: the snapshot store stays
   * CALLER-AUTHORED. `docs/online-runtime-boundary.md` says the caller supplies
   * the database or directory, and `rdap-bootstrap-updater.ts` already settled
   * the house answer by shipping a store interface and no filesystem behind it.
   * A convenience fs store here would be the package's first `node:fs` reach
   * and would quietly take ownership of a directory the caller is meant to own.
   */
  it("ships no filesystem snapshot store for either mirror feed", () => {
    expect(mirrors).not.toHaveProperty("createNodeUrlhausSnapshotStore");
    expect(mirrors).not.toHaveProperty("createNodePhishTankSnapshotStore");
    expect(stripComments(mirrorSources())).not.toMatch(
      /from\s+["']node:(?:fs|fs\/promises|path|os)["']/,
    );
  });

  /**
   * The two feed clients are the package's only concrete network clients that
   * carry a CALLER CREDENTIAL — URLhaus reveals its Auth-Key into a request
   * header, PhishTank its app key into the request PATH. Three source facts are
   * what keep that safe, pinned here because each one is a single line that a
   * later edit could drop without any behavioral test noticing.
   */
  it("keeps the mirror provider clients ambient-free and on the shared address policy", () => {
    const nodeAdapters = new Set([
      "mirror-http-node.ts",
      "urlhaus-node.ts",
      "phishtank-node.ts",
    ]);
    const adapters = stripComments(mirrorSources((name) => nodeAdapters.has(name)));

    // No second place a credential could come from.
    expect(adapters).not.toContain("process.env");
    // No error may quote the URL (PhishTank's key) or a header value
    // (URLhaus's), so nothing is ever built out of a raw Node error message.
    expect(adapters).not.toContain("error.message");
    // The shared address table, not a second block-list primitive.
    expect(adapters).toContain("classifyTransportAddress");
    expect(adapters).not.toContain("BlockList");

    // Everything OUTSIDE those three files stays free of concrete I/O: the
    // parse, index, enricher and updater modules are pure and must remain so.
    const rest = mirrorSources((name) => !nodeAdapters.has(name));
    expect(rest).not.toMatch(/from\s+["']node:(?:dns|net|tls|http|https)["']/);
    expect(rest).not.toMatch(/\bfetch\s*\(/);
  });

  it("routes redirect expansion through the injected L0 session without concrete clients", () => {
    const source = readFileSync(
      join(packageRoot, "src", "resolution", "redirect-chain.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/from\s+["']node:(?:dns|net|tls|http|https)["']/);
    expect(source).not.toMatch(/\bglobalThis\.fetch\s*\(|\bwindow\.fetch\s*\(/);
    expect(source).toContain("session.fetch(");
  });
});
