import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

/**
 * LINK-pnunjxcg — the executable form of `docs/bundle-size-budget.md`.
 *
 * That document recorded a compaction threshold for the generated confusables
 * data and a set of measurements taken by hand on 2026-06-23. Nothing re-took
 * them, so by the time this test was written the *numerator* had not moved by a
 * single byte while the third axis — "5% of the unpacked `linklint` package" —
 * read as 2.3x over budget purely because the denominator had shrunk. A budget
 * that fires when an unrelated package gets smaller is not a budget; that axis
 * is retired in the doc, and the two absolute axes are asserted here.
 *
 * MEASUREMENT METHOD (reproduce it on the command line with `gzip -9 -n`):
 * gzip figures come from `zlib.gzipSync(buf, { level: 9 })`, which emits a
 * HEADERLESS stream. Plain `gzip -9 file` stores the source filename in the
 * header and reports a few bytes more; getting that wrong reads as drift that
 * is not there. The "total" gzip figure is the SUM of the per-file figures, not
 * one gzip over the concatenation: npm reports per-file unpacked sizes, not
 * per-file tarball deltas, so the sum is the honest standalone proxy.
 *
 * WHY THE PROSE ASSERTIONS COVER THE RAW AXIS ONLY (LINK-ujbttpph). The doc
 * used to quote gzip bytes and a gzip percentage too, and this suite asserted
 * the prose matched them. That is a reproducibility claim `gzipSync` does not
 * support: its output depends on the zlib the runtime is linked against, so the
 * same three files measure 8,033 bytes on the maintainer's macOS node
 * (zlib 1.2.12) and 8,168 on the `node:24` and `node:26` Linux images
 * (zlib 1.3.2.1) — identical on both Node majors, which is what ruled the Node
 * version out. Re-baselining would only have moved which machine was wrong.
 * Raw bytes ARE reproducible (measured byte-identical across the same three
 * runtimes), so they stay quoted and asserted. The gzip axis keeps the part
 * that protects the package — the absolute 25 KiB ceiling, asserted against a
 * live measurement above — and loses only the transcript.
 *
 * There is deliberately no `npm pack` shell-out here. Retiring the ratio axis
 * removed the only reason to need one, and an untested subprocess dependency in
 * the check chain costs more than it pays.
 */

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CORE = join(REPO_ROOT, "packages", "core");
const DIST_DATA = join(CORE, "dist", "data");
const DOC = join(REPO_ROOT, "docs", "bundle-size-budget.md");
const prose = readFileSync(DOC, "utf8");

const KIB = 1024;

/** The two absolute axes in `docs/bundle-size-budget.md`. */
const CONFUSABLES_RAW_BUDGET = 250 * KIB; // 256,000
const CONFUSABLES_GZIP_BUDGET = 25 * KIB; // 25,600

/**
 * Browser-bundle thresholds — chosen here, deliberately, because the bundle had
 * no documented one anywhere. `runtime-compat.test.ts` asserted only that the
 * bundle was non-empty, which cannot report a dependency that doubles it.
 *
 * Gated on the MINIFIED output, not the raw one. Unminified bytes move with the
 * comment and identifier volume inside dependencies — a prettier upstream
 * release would move the number without changing a byte of shipped behaviour,
 * and a gate that reports that is a gate people learn to re-baseline.
 *
 * Both axes are kept, for the same reason the confusables budget keeps both:
 * the payload here is a large, highly repetitive data table, so a compressed-
 * only gate could absorb a very large addition of similar data unnoticed.
 *
 * Measured 2026-08-07: 518,278 raw / 145,567 gzip minified (700,149 / 166,771
 * unminified). The thresholds sit at roughly 2x that — this is a drift alarm
 * for an accidentally-added dependency, not a golden value. Two consecutive
 * esbuild runs at each setting produced byte-identical output, so a failure
 * here is a property of the input rather than of the run.
 */
const BUNDLE_MINIFIED_RAW_BUDGET = 1024 * KIB; // 1,048,576
const BUNDLE_MINIFIED_GZIP_BUDGET = 256 * KIB; // 262,144

interface Measurement {
  readonly raw: number;
  readonly gzip: number;
}

const measureBytes = (buf: Buffer | Uint8Array): Measurement => ({
  raw: buf.byteLength,
  gzip: gzipSync(buf, { level: 9 }).byteLength,
});

const measureFile = (...path: string[]): Measurement => measureBytes(readFileSync(join(...path)));

const commas = (n: number): string => n.toLocaleString("en-US");

/**
 * `` | `label` | 79,821 | `` — the exact row the doc has to carry. Raw bytes
 * only: the gzip column was removed from the table because its values are not
 * reproducible off this workstation (see the header note).
 */
const docRow = (label: string, m: Measurement): string => `| ${label} | ${commas(m.raw)} |`;

const pct = (part: number, whole: number): string => ((part / whole) * 100).toFixed(1);

// The emitted artifacts are DISCOVERED, not hard-coded: if `tsc` starts emitting
// a third file (a source map, say) it joins the budget instead of slipping past
// a two-entry list.
const emittedNames = readdirSync(DIST_DATA)
  .filter((name) => name.startsWith("confusables.generated."))
  .sort();

const emitted = emittedNames.map((name) => ({ name, ...measureFile(DIST_DATA, name) }));
const emittedTotal: Measurement = {
  raw: emitted.reduce((sum, f) => sum + f.raw, 0),
  gzip: emitted.reduce((sum, f) => sum + f.gzip, 0),
};

const sourceFile = measureFile(CORE, "src", "data", "confusables.generated.ts");

describe("confusables generated data stays inside its compaction thresholds", () => {
  it("measures the emitted files at all (guards against a silently empty sweep)", () => {
    // Without this, a renamed emit would make the budget trivially satisfiable
    // by measuring nothing at all.
    expect(emittedNames).toEqual(["confusables.generated.d.ts", "confusables.generated.js"]);
    expect(emittedTotal.raw).toBeGreaterThan(50_000);
  });

  it(`unpacked total is under ${commas(CONFUSABLES_RAW_BUDGET)} bytes (250 KiB)`, () => {
    expect(
      emittedTotal.raw,
      "the emitted confusables data crossed its unpacked threshold — see " +
        "docs/bundle-size-budget.md: file a follow-up issue for a compact " +
        "representation with equivalent UTS#39 conformance coverage, do not " +
        "raise this number",
    ).toBeLessThan(CONFUSABLES_RAW_BUDGET);
  });

  it(`gzip total is under ${commas(CONFUSABLES_GZIP_BUDGET)} bytes (25 KiB)`, () => {
    expect(emittedTotal.gzip).toBeLessThan(CONFUSABLES_GZIP_BUDGET);
  });
});

describe("docs/bundle-size-budget.md quotes the measurement, not a memory of it", () => {
  it("carries the current row for each measured artifact", () => {
    const rows = [
      docRow("`packages/core/src/data/confusables.generated.ts`", sourceFile),
      ...emitted.map((f) => docRow(`\`packages/core/dist/data/${f.name}\``, f)),
      docRow("Emitted generated confusables total", emittedTotal),
    ];
    for (const row of rows) {
      expect(
        prose,
        `docs/bundle-size-budget.md is missing the measured row:\n${row}\n` +
          "Update the table — the figures moved.",
      ).toContain(row);
    }
  });

  it("quotes the unpacked axis as a share of its own threshold", () => {
    expect(prose).toContain(`${pct(emittedTotal.raw, CONFUSABLES_RAW_BUDGET)}%`);
  });

  it("quotes no measured gzip figure that a reader could re-baseline against", () => {
    // The complement of the row assertion above: the doc has to carry the raw
    // measurements and must NOT carry the gzip ones. Without this the table's
    // gzip column could be restored by hand and go unnoticed until a runner
    // with a different zlib build reported it — the LINK-ujbttpph failure.
    // Every figure checked here is a LIVE reading, so the assertion means the
    // same thing on macOS and on the Linux images rather than banning one
    // machine's transcript and admitting the other's.
    // Checked as a whole ROW rather than as a bare number: `| label | raw |`
    // is a prefix of `| label | raw | gzip |`, so the assertion above would
    // stay green against a restored third column, and a bare `238` is short
    // enough to collide with an unrelated digit run.
    const threeColumn = [
      [`\`packages/core/src/data/confusables.generated.ts\``, sourceFile] as const,
      ...emitted.map((f) => [`\`packages/core/dist/data/${f.name}\``, f] as const),
      ["Emitted generated confusables total", emittedTotal] as const,
    ].map(([label, m]) => `${docRow(label, m)} ${commas(m.gzip)} |`);

    for (const row of threeColumn) {
      expect(
        prose,
        `docs/bundle-size-budget.md carries a gzip column:\n${row}\nGzip bytes ` +
          "are a property of the runtime's zlib build as well as of the input, " +
          "so a quoted one is wrong on some machine by construction — state the " +
          "absolute threshold instead (LINK-ujbttpph).",
      ).not.toContain(row);
    }

    // The prose figures the doc used to carry beside the raw ones.
    expect(prose).not.toContain(`${commas(emittedTotal.gzip)} bytes gzip`);
    expect(prose).not.toContain(`${pct(emittedTotal.gzip, CONFUSABLES_GZIP_BUDGET)}%`);
  });

  it("states both absolute thresholds in bytes", () => {
    expect(prose).toContain(`${commas(CONFUSABLES_RAW_BUDGET)} bytes`);
    expect(prose).toContain(`${commas(CONFUSABLES_GZIP_BUDGET)} bytes`);
  });

  it("lists exactly the two absolute axes — the ratio axis stays retired", () => {
    // The retirement is a decision, not an oversight (see the doc's own section
    // on it). This assertion is what stops a future reader restoring a "5% of
    // the package" bullet on the grounds that it looks like it fell out.
    const start = prose.search(/^## Compaction threshold$/m);
    expect(start).toBeGreaterThan(-1);
    const rest = prose.slice(start + 1);
    const end = rest.search(/^## /m);
    const section = end === -1 ? rest : rest.slice(0, end);

    const bullets = section.split("\n").filter((line) => line.startsWith("- "));
    expect(bullets).toHaveLength(2);
    expect(section).toContain("250 KiB");
    expect(section).toContain("25 KiB");
    expect(section).not.toMatch(/%\s+of the unpacked/);
  });

  // LINK-qbbegjro — the pin. Every prose assertion in this suite matches
  // against the file's RAW bytes, so where the author's editor happened to wrap
  // a line decides whether a guard fires. That is not hypothetical here: until
  // LINK-ujbttpph reworded it, the decision sentence in the section guarded
  // directly above read "31.3% of the" / "unpacked threshold" across two lines
  // — the forbidden phrasing, inside the guarded section, with the wrap falling
  // between "the" and "unpacked". The guard reported green the whole time. It
  // was inert, not satisfied.
  it("pins the defect: a line wrap decides whether the forbidden phrasing is caught", () => {
    const guard = /%\s+of the unpacked/;
    const onOneLine = "31.3% of the unpacked threshold";
    const asItShipped = "31.3% of the\nunpacked threshold";

    expect(onOneLine).toMatch(guard);
    // Same words, wrapped one column earlier, and the guard goes quiet.
    expect(asItShipped).not.toMatch(guard);
  });
});

describe("browser bundle stays inside its byte gate", () => {
  it(
    "minifies under 1 MiB raw and 256 KiB gzip",
    async () => {
      // Same esbuild settings as the compatibility bundle in
      // runtime-compat.test.ts, plus minify — that suite proves the bundle
      // BUILDS for the browser, this one prices it.
      const result = await build({
        entryPoints: [join(CORE, "dist", "index.js")],
        bundle: true,
        write: false,
        platform: "browser",
        format: "esm",
        target: "es2022",
        logLevel: "silent",
        minify: true,
      });
      expect(result.errors).toEqual([]);

      const output = result.outputFiles?.[0];
      expect(output, "esbuild produced no output file").toBeDefined();
      const bundle = measureBytes((output as { contents: Uint8Array }).contents);

      // Floor first: a bundle that collapsed to nothing would pass both ceilings.
      expect(bundle.raw).toBeGreaterThan(100_000);
      expect(
        bundle.raw,
        `minified bundle is ${commas(bundle.raw)} bytes; budget is ` +
          `${commas(BUNDLE_MINIFIED_RAW_BUDGET)}. Check what dependency was added.`,
      ).toBeLessThan(BUNDLE_MINIFIED_RAW_BUDGET);
      expect(
        bundle.gzip,
        `minified+gzip bundle is ${commas(bundle.gzip)} bytes; budget is ` +
          `${commas(BUNDLE_MINIFIED_GZIP_BUDGET)}.`,
      ).toBeLessThan(BUNDLE_MINIFIED_GZIP_BUDGET);
    },
    // esbuild is fast, but the default 5 s vitest timeout is not a reliable gate
    // on a loaded machine — see confusables-drift.test.ts for the ~50x load
    // multiplier that motivated the same allowance there.
    60_000,
  );

  it("documents the same thresholds it enforces", () => {
    expect(prose).toContain(`${commas(BUNDLE_MINIFIED_RAW_BUDGET)} bytes`);
    expect(prose).toContain(`${commas(BUNDLE_MINIFIED_GZIP_BUDGET)} bytes`);
  });
});
