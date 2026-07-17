import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as online from "../src/index.js";
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

  it("keeps fixture infrastructure internal and the root side-effect free", () => {
    expect(Object.keys(online)).toEqual([]);
    expect(manifest.exports).not.toHaveProperty("./testing");
    expect(manifest.exports).toHaveProperty("./transport");
    expect(manifest.exports).toHaveProperty("./resolution");
    expect(transport.createSafeTransport).toBeTypeOf("function");
    expect(transport.createNodeSafeTransport).toBeTypeOf("function");
    expect(transport.classifyTransportAddress).toBeTypeOf("function");
    const transportExport = manifest.exports["./transport"] as Record<string, string>;
    expect(Object.keys(transportExport)).toEqual(["types", "default"]);
    expect(resolution.decodeEmbeddedWrapper).toBeTypeOf("function");
    expect(resolution.createEmbeddedWrapperEnricher).toBeTypeOf("function");
    const resolutionExport = manifest.exports["./resolution"] as Record<string, string>;
    expect(Object.keys(resolutionExport)).toEqual(["types", "default"]);
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
    const source = readdirSync(resolutionDir)
      .filter((name) => name.endsWith(".ts"))
      .map((name) => readFileSync(join(resolutionDir, name), "utf8"))
      .join("\n");

    expect(source).not.toMatch(/from\s+["']node:(?:dns|net|tls|http|https)["']/);
    expect(source).not.toMatch(/\bfetch\s*\(/);
    expect(source).not.toContain("tap-api-v2.proofpoint.com/v2/url/decode");
  });
});
