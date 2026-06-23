import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";
import * as metadata from "../src/metadata.js";
import * as experimental from "../src/experimental.js";
import * as data from "../src/data.js";
import * as detectorRegistry from "../src/detectors/registry.js";
import { CHECKS } from "../src/detectors/checks.js";

/**
 * Contract tests for the curated secondary entry points (LINK-kflglaxa).
 *
 * These lock the ADDITIVE subpaths (`linklint/metadata`, `linklint/experimental`,
 * `linklint/data`) to their intended runtime surface, lock the package.json
 * `exports` map (including `types`-before-`default` conditional ordering), and
 * enforce adapter discipline (cli/mcp must not deep-import core internals).
 *
 * Root decision: keep a legacy/advanced compatibility window. `inspect()` and
 * schema/metadata exports are the stable root surface; detector, policy,
 * parser, unicode, and reference-data helpers remain available from root for
 * compatibility, but new advanced consumers should prefer the curated subpaths.
 */

// Resolve paths relative to THIS module so the test holds regardless of cwd.
const thisDir = dirname(fileURLToPath(import.meta.url));
// packages/core/test -> repo root is three levels up.
const repoRoot = join(thisDir, "..", "..", "..");

describe("linklint/metadata — curated runtime surface", () => {
  it("exposes exactly the metadata value exports", () => {
    expect(Object.keys(metadata).sort()).toEqual(
      ["DATA_VERSIONS", "WEIGHTS", "WEIGHTS_VERSION", "reasonMeta", "weightFor"].sort(),
    );
  });
});

describe("linklint/experimental — curated runtime surface", () => {
  it("exposes exactly the experimental value exports", () => {
    // Type-only re-exports (Detector, DetectorFinding, InspectionContext) do not
    // appear at runtime, so they are intentionally absent here.
    expect(Object.keys(experimental).sort()).toEqual(
      [
        "DETECTORS",
        "normalizationDelta",
        "confusableChar",
        "mixedScript",
        "asciiHomoglyph",
        "invisibleChar",
        "bidiOverride",
        "userinfoPresent",
        "ipObfuscation",
        "ipClassification",
        "embeddedDomain",
        "riskyTld",
        "fileExtensionTld",
        "encodingObfuscation",
        "dangerousScheme",
        "confusableInPath",
        "brandLookalike",
        "skeletonCollision",
        "latinSkeletonHomograph",
        "idnHost",
        "soundsquatting",
        "bitsquatting",
        "baitTokens",
        "openRedirectParam",
        "suspiciousExtension",
        "punycodeMalformed",
        "excessiveSubdomainDepth",
        "promptInjection",
        "apiEndpointImpersonation",
        "credentialHarvesting",
        "dataExfiltration",
        "ssrfCloudMetadata",
        "scanAmbiguousAuthority",
        "scanSeparatorLookalike",
        "scanIdnaMappingAmbiguity",
        "scanControlChar",
        "runPolicy",
        "policyConfigured",
        "parse",
        "findConfusables",
        "skeleton",
      ].sort(),
    );
  });

  it("has a named detector export for every parsed check descriptor", () => {
    const parsedChecks = CHECKS.filter((check) => check.phase === "parsed");
    const namedDetectorIds = new Set<string>();
    for (const [name, value] of Object.entries(detectorRegistry) as [string, unknown][]) {
      if (name !== "DETECTORS" && isDetectorLike(value)) {
        namedDetectorIds.add(value.id);
      }
    }

    expect([...namedDetectorIds].sort()).toEqual(
      parsedChecks.map((check) => check.id).sort(),
    );
  });
});

describe("linklint root — legacy advanced compatibility surface", () => {
  it("continues to expose the complete experimental surface from root", () => {
    for (const key of Object.keys(experimental)) {
      expect(root).toHaveProperty(key);
    }
  });
});

describe("linklint/data — curated runtime surface", () => {
  it("exposes exactly the reference-data value exports", () => {
    // BrandEntry is type-only and does not appear at runtime.
    expect(Object.keys(data).sort()).toEqual(
      ["RISKY_TLDS", "FILE_EXTENSION_TLDS", "BRAND_DOMAINS", "BRAND_WATCHLIST"].sort(),
    );
  });
});

function isDetectorLike(value: unknown): value is { id: string; run: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    "run" in value &&
    typeof (value as { id: unknown }).id === "string"
  );
}

describe("package.json exports map declares the secondary entry points", () => {
  type Conditional = Record<string, string>;
  const manifest = JSON.parse(
    readFileSync(join(repoRoot, "packages", "core", "package.json"), "utf8"),
  ) as { exports: Record<string, Conditional> };

  it.each(["./metadata", "./experimental", "./data"])(
    "declares the %s subpath",
    (subpath) => {
      expect(manifest.exports[subpath]).toBeDefined();
    },
  );

  it.each(["./metadata", "./experimental", "./data"])(
    "%s orders 'types' before 'default'",
    (subpath) => {
      const block = manifest.exports[subpath];
      expect(block).toBeDefined();
      const keys = Object.keys(block ?? {});
      expect(keys[0]).toBe("types");
      expect(keys).toContain("default");
      expect(keys.indexOf("types")).toBeLessThan(keys.indexOf("default"));
    },
  );
});

describe("adapter discipline — cli/mcp must not deep-import core internals", () => {
  const adapterDirs = [
    join(repoRoot, "packages", "cli", "src"),
    join(repoRoot, "packages", "mcp", "src"),
  ];

  /** Recursively collect every *.ts file under a directory. */
  function collectTsFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        out.push(...collectTsFiles(full));
      } else if (entry.isFile() && entry.name.endsWith(".ts")) {
        out.push(full);
      }
    }
    return out;
  }

  // Match `from "<spec>"` / `from '<spec>'` import specifiers.
  const importSpecifier = /\bfrom\s+["']([^"']+)["']/g;

  /** A specifier is forbidden if it reaches into core internals or the
   *  non-stable secondary entry points. */
  function isForbidden(spec: string): boolean {
    if (spec.includes("packages/core/src")) return true;
    // Any relative path that climbs into a core source tree.
    if (spec.includes("core/src")) return true;
    if (spec === "linklint/experimental" || spec.startsWith("linklint/experimental/")) return true;
    if (spec === "linklint/data" || spec.startsWith("linklint/data/")) return true;
    return false;
  }

  const files = adapterDirs.flatMap(collectTsFiles);

  it("finds adapter source files to scan", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it("no adapter file deep-imports core internals or non-stable subpaths", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(importSpecifier)) {
        const spec = match[1] ?? "";
        if (isForbidden(spec)) {
          offenders.push(`${file}: import from "${spec}"`);
        }
      }
    }
    expect(offenders, `forbidden core deep-imports:\n${offenders.join("\n")}`).toEqual([]);
  });
});
