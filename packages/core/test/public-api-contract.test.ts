import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { inspect } from "../src/index.js";
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
const publicReadme = readFileSync(join(repoRoot, "README.md"), "utf8");
const coreReadme = readFileSync(join(repoRoot, "packages", "core", "README.md"), "utf8");
const architectureDoc = readFileSync(join(repoRoot, "docs", "architecture.md"), "utf8");
const enrichmentDoc = readFileSync(
  join(repoRoot, "docs", "enrichment-outcomes.md"),
  "utf8",
);
const guaranteeRegister = readFileSync(join(repoRoot, "docs", "guarantees.md"), "utf8");

/**
 * Collapse a markdown document to one whitespace-normalized line so an assertion
 * matches the CLAIM rather than the line breaks that happen to sit inside it.
 *
 * Two failure modes this repository has already paid for, both of which make an
 * assertion pass by matching NOTHING:
 *
 *   1. A hard wrap mid-sentence. `toContain("same input + same package version")`
 *      silently stops matching the moment a reflow puts a newline after `+`.
 *   2. Blockquote markers. `> ` SURVIVES whitespace flattening — joining lines
 *      and collapsing runs leaves `claim > continued` — so the marker has to be
 *      stripped per line, BEFORE the join.
 */
const flattenProse = (markdown: string): string =>
  markdown
    .split("\n")
    .map((line) => line.replace(/^\s*>+\s?/, ""))
    .join(" ")
    .replace(/\s+/g, " ");

describe("InspectResult schema contract (schemaVersion + confidence, FR-SCORE-2b)", () => {
  it("stamps schemaVersion 1.13 on ok and invalid results", () => {
    expect(inspect("https://www.example.com/").schemaVersion).toBe("1.13");
    expect(inspect("ht!tp://%%%not a url").schemaVersion).toBe("1.13");
  });

  it("deterministic lexical results (ok AND invalid) carry confidence 1.0", () => {
    const ok = inspect("https://www.example.com/");
    expect(ok.status).toBe("ok");
    expect(ok.confidence).toBe(1);

    const risky = inspect("https://paypal.com@xn--pypal-4ve.ru/login");
    expect(risky.confidence).toBe(1);

    const invalid = inspect("ht!tp://%%%not a url");
    expect(invalid.status).toBe("invalid");
    expect(invalid.confidence).toBe(1);
  });

  it("carries the PSL snapshot provenance on ok AND invalid results (schema 1.2)", () => {
    // Provenance travels even on invalid input, so a parse failure is still
    // reproducible against a known trust-boundary snapshot (LINK-rkhuihjx).
    for (const input of ["https://www.example.com/", "ht!tp://%%%not a url"]) {
      const snap = inspect(input).pslSnapshot;
      // Deterministic provenance date: whatever the pinned snapshot records,
      // unchanged, on every result. Read off the record rather than repeated as
      // a literal — `psl-provenance.test.ts` and `data-versions.test.ts` are
      // what pin the record itself to the installed tldts, so duplicating the
      // date here only adds a place for a pin bump to break spuriously.
      expect(snap.date).toBe(metadata.PSL_PROVENANCE.pslListDate);
      // Advisory, time-relative staleness against the default 180-day window.
      expect(typeof snap.stale === "boolean" || snap.stale === null).toBe(true);
      // …and one-directional (LINK-elzuacby): the pinned date is a packaging
      // proxy that bounds the snapshot's age from BELOW, so it can prove
      // staleness but never freshness. `false` is unreachable from it at any
      // clock reading — this holds on every calendar date, not just today.
      expect(snap.stale).not.toBe(false);
    }
  });
});

/**
 * LINK-ltyjctpf — the README publishes `inspect()` as **synchronous** and
 * **deterministic** ("same input + same pinned data versions → same verdict"),
 * and `docs/architecture.md` §0 opens with the same two words. Both were
 * load-bearing prose with no test behind them: `runtime-compat.test.ts` pins the
 * *inputs* to determinism (no network/native imports) but nothing asserted the
 * property itself, and nothing stopped `inspect` from being made async.
 *
 * `pslSnapshot.stale` is the one deliberate exception — advisory, time-relative,
 * and documented as such on `PslSnapshot`. It is excluded here rather than
 * ignored, so the carve-out stays visible instead of weakening the claim.
 */
describe("inspect() is synchronous and deterministic (published guarantee)", () => {
  const CORPUS = [
    "https://www.example.com/path",
    "https://paypal.com@evil.example.com/login",
    "https://www.gооgle.com@bad.tk/login",
    "https://paypa1.com/",
    "https://xn--pypal-4ve.ru/signin",
    "http://169.254.169.254/latest/meta-data/",
    "https://a.b.c.d.e.example.com/",
    "ht!tp://%%%not a url",
    "",
  ];

  it("returns a plain result, not a Promise", () => {
    for (const input of CORPUS) {
      const result = inspect(input);
      expect(result, input).not.toBeInstanceOf(Promise);
      expect((result as { then?: unknown }).then, input).toBeUndefined();
    }
  });

  it("returns a deep-equal result for the same input on every call", () => {
    for (const input of CORPUS) {
      expect(inspect(input), input).toEqual(inspect(input));
    }
  });

  // Order-independence of the corpus: a detector holding state across calls
  // would make the verdict depend on what was inspected before it.
  it("carries no state between calls (reversed order gives the same verdicts)", () => {
    const forward = CORPUS.map((input) => inspect(input));
    const reverse = [...CORPUS].reverse().map((input) => inspect(input));
    expect(forward).toEqual([...reverse].reverse());
  });

  it("depends on no clock except the advisory pslSnapshot.stale flag", () => {
    const strip = (result: ReturnType<typeof inspect>): unknown => {
      const { pslSnapshot, ...rest } = result;
      return { ...rest, pslSnapshot: { date: pslSnapshot.date } };
    };

    const before = CORPUS.map((input) => strip(inspect(input)));
    vi.useFakeTimers();
    try {
      // Far enough forward to cross the 180-day PSL freshness window, so the
      // one field that IS allowed to move actually moves.
      vi.setSystemTime(new Date("2031-01-01T00:00:00Z"));
      expect(CORPUS.map((input) => strip(inspect(input)))).toEqual(before);
    } finally {
      vi.useRealTimers();
    }
  });

  // The strongest reading of "no state carried between calls": a SECOND
  // instance of the module graph must agree with the first. Repeat-call and
  // reversed-order equality above both observe one already-initialized module
  // registry, so a lazily-built table that is mutated on first use — a memo
  // keyed on something it should not be, a detector array sorted in place —
  // can survive both. Re-importing under a reset registry compares a warm
  // instance against a cold one and reddens on exactly that.
  it("carries no module-scope state either (a cold re-import agrees with the warm one)", async () => {
    const warm = CORPUS.map((input) => inspect(input));
    vi.resetModules();
    const cold = await import("../src/index.js");
    expect(cold.inspect).not.toBe(inspect);
    expect(CORPUS.map((input) => cold.inspect(input))).toEqual(warm);
  });

  /**
   * The ANTECEDENT is the load-bearing half of A3, and it was wrong.
   *
   * The published claim was "same input + same pinned DATA VERSIONS → same
   * verdict". False, and falsifiable from the history: `5813e01` added the
   * `fqdn_root_label` detector and its reason code, changing `reasons[]` for
   * every fully-qualified host, with `schema/base.ts` and `scoring/weights.ts`
   * both untouched and no `DataVersions` field moved. Same input, same data
   * versions, different verdict.
   *
   * It is structural rather than careless. `DataVersions` stamps the DATA (PSL,
   * confusables, IP ranges, IDNA), `WEIGHTS_VERSION` stamps the WEIGHTS, and
   * NEITHER stamps detector logic — a weight-0 informational detector moves
   * neither by design, because there is no weight to bump.
   *
   * The deeper defect: `DataVersions` is an EMITTED stamp, not a pinnable
   * input. No caller can install "linklint at data versions X"; they install a
   * package version and are handed whatever data it ships. The old antecedent
   * named something the caller cannot control while omitting the one thing they
   * can, which is also where `docs/architecture.md` §6.4's own matrix already
   * assigns detector-logic changes ("package version + CHANGELOG.md").
   *
   * The previous assertion here was `toContain("**Deterministic**")` — a bare
   * adjective that stays green under ANY antecedent, including the false one.
   * A guarantee whose pin does not bite is the same defect in a different
   * place, so this matches the whole conditional, both ways.
   */
  it("publishes the determinism antecedent a caller can actually pin", () => {
    const CORRECTED = "same input + same package version → same verdict";
    const FALSIFIED = "same pinned data versions";

    // The register NARRATES the old wording — it quotes the claims it tracks,
    // which is the same reason it is exempt from its own claim budget. So the
    // refusal below is scoped to A3's ROW, not to the whole document: the row
    // is the claim, the prose around it is the history of the claim.
    const registerRow = flattenProse(guaranteeRegister)
      .split("|")
      .map((cell) => cell.trim())
      .find((cell) => cell.startsWith("Deterministic —"));

    expect(
      registerRow,
      "docs/guarantees.md has no A3 row starting `Deterministic —`. If the row " +
        "was reworded, this assertion is matching nothing and has stopped checking.",
    ).toBeDefined();

    for (const [name, prose] of [
      ["README.md", flattenProse(publicReadme)],
      ["docs/guarantees.md (A3 row)", registerRow as string],
    ] as const) {
      expect(prose, `${name} must state the antecedent as the package version`).toContain(
        CORRECTED,
      );
      expect(
        prose,
        `${name} still conditions determinism on the data versions. DataVersions ` +
          "stamps no detector logic and is not a pinnable input — see 5813e01.",
      ).not.toContain(FALSIFIED);
    }

    // The same false inference, restated in the scoring section: version-pinned
    // weights and data sources do NOT make a verdict reproducible, for exactly
    // the reason above — `dataVersions` stamps no detector logic. Refused
    // separately because it reaches the conclusion without quoting the
    // antecedent, so the phrase-level check above walks straight past it.
    expect(
      flattenProse(publicReadme),
      "README.md still derives reproducibility from `dataVersions` alone.",
    ).not.toContain("so verdicts are reproducible");

    // §0 states the bare adjective and no antecedent, which is why it is not
    // asserted against the conditional above. Swept, and deliberately clean.
    expect(architectureDoc).toContain("synchronous, deterministic");
  });
});

describe("async enrichment public boundary and documentation contract (K9)", () => {
  it("exports the runtime orchestration, validation, cache, and version surface", () => {
    expect(root.SCHEMA_VERSION).toBe("1.13");
    expect(root.ENRICHMENT_SCHEMA_VERSION).toBe("1.0");
    expect(root.inspectAsync).toBeTypeOf("function");
    expect(root.isEnrichmentReport).toBeTypeOf("function");
    expect(root.InMemoryEnrichmentCache).toBeTypeOf("function");
    expect(root.InMemoryEnrichmentGovernor).toBeTypeOf("function");
  });

  it("keeps public schema and async cache documentation aligned with the code", () => {
    expect(publicReadme).toContain(`schemaVersion: '${root.SCHEMA_VERSION}'`);
    expect(publicReadme).toContain("enrichment?: EnrichmentReport");
    expect(publicReadme).toContain("cacheTtlMsFor(report, context)");

    expect(coreReadme).toContain("inspectAsync()");
    expect(coreReadme).toContain("Promise-capable stores");
    expect(coreReadme).toContain("cacheTtlMsFor(report, context)");

    expect(architectureDoc).toContain(`schema version \`${root.SCHEMA_VERSION}\``);
    expect(architectureDoc).toContain(`schemaVersion: '${root.SCHEMA_VERSION}'`);
    expect(architectureDoc).not.toContain("schemaVersion: '1.2';");
    expect(architectureDoc).toContain("enrichment?: EnrichmentReport");

    expect(enrichmentDoc).toContain("Promise-capable external stores");
    expect(enrichmentDoc).toContain("cache-ttl-error");
    expect(enrichmentDoc).toContain("explicit negative result");
    expect(enrichmentDoc).toContain("invalid-cached-output");
  });
});

describe("linklint/metadata — curated runtime surface", () => {
  it("exposes exactly the metadata value exports", () => {
    expect(Object.keys(metadata).sort()).toEqual(
      [
        "DATA_VERSIONS",
        "PSL_PROVENANCE",
        "WEIGHTS",
        "WEIGHTS_VERSION",
        "pslOutdated",
        "reasonMeta",
        "weightFor",
      ].sort(),
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
        "headerShapedToken",
        "hostLengthUnresolvable",
        "specialUseName",
        "fqdnRootLabel",
        "invisibleChar",
        "bidiOverride",
        "userinfoPresent",
        "ipObfuscation",
        "ipClassification",
        "classifyHost",
        "ambiguousNumericHost",
        "embeddedDomain",
        "fileExtensionTld",
        "encodingObfuscation",
        "dangerousScheme",
        "confusableInPath",
        "brandHomoglyph",
        "skeletonCollision",
        "latinSkeletonHomograph",
        "localeCaseCollapse",
        "lowByteTruncation",
        "idnHost",
        "openRedirectParam",
        "suspiciousExtension",
        "punycodeMalformed",
        "idnaProtocolViolation",
        "percentEncodingMalformed",
        "excessiveSubdomainDepth",
        "promptInjection",
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
      ["FILE_EXTENSION_TLDS", "BRAND_DOMAINS", "BRAND_WATCHLIST"].sort(),
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
