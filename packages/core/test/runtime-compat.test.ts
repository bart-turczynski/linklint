import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";
// Import from the PUBLISHED package export (dist), not the source — proves the
// package metadata/exports actually resolve (SC-4).
import { inspect } from "linklint";

const here = dirname(fileURLToPath(import.meta.url));
const distEntry = resolve(here, "../dist/index.js");
const srcDir = resolve(here, "../src");

// D4 — Node/browser/edge runtime compatibility (SC-4).
describe("Node runtime (package export)", () => {
  it("imports inspect() from the package and runs representative inputs", () => {
    expect(typeof inspect).toBe("function");
    expect(inspect("https://example.com/").status).toBe("ok");
    expect(inspect("https://paypal.com@evil.com/").severity).toBe("medium");
    expect(inspect("ht!tp://%%%x").status).toBe("invalid");
  });
});

describe("no native / node-only / network dependencies (offline, embeddable)", () => {
  function walk(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
      const p = join(dir, name);
      return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
    });
  }

  it("core source imports no node: builtins or network/native modules", () => {
    const forbidden = /from\s+["'](node:|fs|net|http|https|dns|child_process|tls|worker_threads)["']/;
    const offenders: string[] = [];
    for (const file of walk(srcDir)) {
      if (forbidden.test(readFileSync(file, "utf8"))) offenders.push(file);
    }
    expect(offenders, `node-only imports found: ${offenders.join(", ")}`).toEqual([]);
  });
});

describe("browser/edge bundle (SC-4)", () => {
  it("bundles for the browser platform with no node externals", async () => {
    const result = await build({
      entryPoints: [distEntry],
      bundle: true,
      write: false,
      platform: "browser",
      format: "esm",
      target: "es2022",
      logLevel: "silent",
    });
    expect(result.errors).toEqual([]);
    // Sanity: the bundle is non-empty and contains the public API.
    const code = result.outputFiles?.[0]?.text ?? "";
    expect(code.length).toBeGreaterThan(0);
    expect(code).toMatch(/inspect/);
  });
});
