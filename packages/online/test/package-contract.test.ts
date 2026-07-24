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
    const transportExport = manifest.exports["./transport"] as Record<string, string>;
    expect(Object.keys(transportExport)).toEqual(["types", "default"]);
    expect(resolution.decodeEmbeddedWrapper).toBeTypeOf("function");
    expect(resolution.createEmbeddedWrapperEnricher).toBeTypeOf("function");
    expect(resolution.createRedirectChainEnricher).toBeTypeOf("function");
    const resolutionExport = manifest.exports["./resolution"] as Record<string, string>;
    expect(Object.keys(resolutionExport)).toEqual(["types", "default"]);
    expect(reputation.fetchRdapDomain).toBeTypeOf("function");
    expect(reputation.resolveRdapBase).toBeTypeOf("function");
    expect(reputation.RDAP_SOURCE_DESCRIPTOR).toBeTypeOf("object");
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
