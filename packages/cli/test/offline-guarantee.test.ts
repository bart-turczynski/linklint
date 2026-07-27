import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * `packages/cli/README.md` publishes a `## Guarantees` section promising **no
 * outbound network** and **no telemetry** (v1). Until LINK-ltyjctpf that was
 * load-bearing prose with nothing behind it — core had `runtime-compat.test.ts`
 * pinning the equivalent claim, the CLI had nothing.
 *
 * The precedent is LINK-zsbeqtcr: an unqualified "inspect() never throws" that
 * turned out to be false for non-string input. A published guarantee that no
 * test can break is indistinguishable from one that is already broken.
 *
 * Unlike core, the CLI legitimately reads the filesystem (stdin, `--file`), so
 * this pins the network/telemetry half only.
 */

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = resolve(here, "../src");
const packageJsonPath = resolve(here, "../package.json");
const readmePath = resolve(here, "../README.md");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
  });
}

describe("@linklint/cli — no outbound network, no telemetry (published guarantee)", () => {
  const sources = walk(srcDir);

  it("finds source files to scan (guards against a silently empty sweep)", () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  // Static import scan. A transport the CLI cannot import is a transport it
  // cannot use; `node:fs`/`node:util`/`node:module` stay allowed deliberately.
  it("imports no network or IPC module", () => {
    const forbidden =
      /from\s+["'](node:)?(net|tls|http|https|http2|dgram|dns|child_process|worker_threads|cluster|inspector)["']/;
    const offenders = sources.filter((f) => forbidden.test(readFileSync(f, "utf8")));
    expect(offenders, `network/IPC imports found: ${offenders.join(", ")}`).toEqual([]);
  });

  // Imports are not the only door: fetch/XHR/WebSocket are globals in modern
  // Node, so a call needs no import at all.
  it("calls no ambient network global", () => {
    const forbidden = /\b(fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon)\s*\(/;
    const offenders = sources.filter((f) => forbidden.test(readFileSync(f, "utf8")));
    expect(offenders, `ambient network calls found: ${offenders.join(", ")}`).toEqual([]);
  });

  // A dependency that can reach the network makes the guarantee unauditable by
  // source scan alone, so the dependency set itself is pinned.
  it("depends only on the offline core package", () => {
    const pkg = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
      dependencies?: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(["linklint"]);
  });

  it("still publishes the guarantee it is pinning", () => {
    const readme = readFileSync(readmePath, "utf8");
    expect(readme).toContain("## Guarantees");
    expect(readme).toContain("**No outbound network**");
    expect(readme).toContain("no telemetry");
  });
});
