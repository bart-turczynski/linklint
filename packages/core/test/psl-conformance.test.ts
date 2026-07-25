import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as tldtsParse } from "tldts";
import { describe, expect, it } from "vitest";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { inspect } from "../src/index.js";
import { analyzeHost } from "../src/parse/psl.js";

/**
 * U2 (LINK-rumbzijk) — the FULL upstream Public Suffix List `tests.txt` run
 * against linklint's bundled PSL data, not a hand-picked slice of it.
 *
 * Why a full corpus: linklint's eTLD+1 boundary comes from the PSL snapshot
 * bundled inside `tldts` (pinned as `dataVersions.publicSuffixList`). A routine
 * `tldts` bump can silently move wildcard handling, exception nesting, or the
 * no-rule-matches default, and the six hand-picked rows in `psl.test.ts` would
 * not notice. This asserts every upstream vector on every run.
 *
 * The corpus is committed at `test/data/psl-tests.txt` and pinned by sha256, so
 * this suite is offline and byte-reproducible — same contract as the IANA range
 * snapshots in `ip-ranges.test.ts`.
 *
 * DIVERGENCES ARE ENUMERATED, NOT WAIVED. The ledger below is exact in both
 * directions: an undeclared divergence fails, and so does a ledger entry that
 * stopped diverging. Each class carries a positive proof of its cause rather
 * than an allowlist entry.
 */

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CORPUS = join(REPO_ROOT, "packages", "core", "test", "data", "psl-tests.txt");

/** Provenance — see test/data/README.md. Byte-stable upstream since 2016. */
const SOURCE_URL = "https://raw.githubusercontent.com/publicsuffix/list/main/tests/tests.txt";
const PINNED_SHA256 = "61a3a502cf471d1a919d5e43c10e910023b0c4230e1db506f8e2ff0b47d2234e";
const EXPECTED_ROWS = 78;

interface Vector {
  /** `null` for the upstream "null input" row, which a string API cannot take. */
  readonly input: string | null;
  /** Upstream expected registrable domain (eTLD+1). */
  readonly expected: string | null;
}

/**
 * Upstream format: one `input expected` pair per line, `null` as a literal
 * token, `//` line comments (which also disable the non-Internet `.local` rows).
 */
function parseCorpus(text: string): Vector[] {
  const vectors: Vector[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("//")) continue;
    const parts = line.split(/\s+/);
    // A row that is not exactly two tokens means the upstream format changed;
    // fail loudly rather than silently skipping vectors.
    expect(parts, `unparseable corpus row: ${line}`).toHaveLength(2);
    const token = (t: string) => (t === "null" ? null : t);
    vectors.push({ input: token(parts[0] as string), expected: token(parts[1] as string) });
  }
  return vectors;
}

const corpusBytes = readFileSync(CORPUS);
const VECTORS = parseCorpus(corpusBytes.toString("utf8"));
const HOST_VECTORS = VECTORS.filter((v): v is Vector & { input: string } => v.input !== null);

/** The two classes in which linklint deliberately differs from upstream. */
type DivergenceClass = "private-section" | "empty-label";

interface Divergence {
  readonly cls: DivergenceClass;
  /** What linklint actually returns. Pinned, so a silent move fails. */
  readonly linklint: string | null;
}

const LEDGER: ReadonlyMap<string, Divergence> = new Map([
  // ── CLASS 1: PRIVATE-section suffixes (4 rows) ────────────────────────────
  // `uk.com` is registered in the PSL's PRIVATE section. Upstream `tests.txt`
  // exercises the FULL list; linklint resolves ICANN-only on purpose, so that a
  // private suffix stays a registrable domain and an embedded `github.io` is
  // still seen as an authority by FR-D-8 (`src/parse/psl.ts:20-22`). Reaffirmed
  // as a standing boundary decision by Epic T (LINK-yfejldva).
  ["uk.com", { cls: "private-section", linklint: "uk.com" }],
  ["example.uk.com", { cls: "private-section", linklint: "uk.com" }],
  ["b.example.uk.com", { cls: "private-section", linklint: "uk.com" }],
  ["a.b.example.uk.com", { cls: "private-section", linklint: "uk.com" }],
  // ── CLASS 2: leading empty label (2 rows) ─────────────────────────────────
  // tldts tolerates a leading dot and resolves the host anyway. linklint's own
  // parser rejects an empty label first (`src/parse/raw-parts.ts:152-153`), so
  // this input never reaches the PSL layer through the public API. Asserted
  // below rather than assumed.
  [".example.com", { cls: "empty-label", linklint: "example.com" }],
  [".example.example", { cls: "empty-label", linklint: "example.example" }],
] satisfies ReadonlyArray<readonly [string, Divergence]>);

const inClass = (cls: DivergenceClass) =>
  [...LEDGER.entries()].filter(([, d]) => d.cls === cls).map(([host]) => host);

describe("PSL conformance corpus provenance", () => {
  it("is the pinned upstream file, byte for byte", () => {
    expect(createHash("sha256").update(corpusBytes).digest("hex")).toBe(PINNED_SHA256);
    expect(corpusBytes.includes("\r".charCodeAt(0))).toBe(false); // LF-only (see AGENTS.md)
    expect(corpusBytes.toString("utf8")).toContain("dedicated to the Public Domain");
  });

  it("parses to the expected shape (guards against an upstream format change)", () => {
    expect(VECTORS).toHaveLength(EXPECTED_ROWS);
    // Exactly one row has a null input; it is not applicable to a string API.
    expect(VECTORS.length - HOST_VECTORS.length).toBe(1);
    // Sanity: the corpus really does carry the interesting rule shapes.
    const inputs = new Set(HOST_VECTORS.map((v) => v.input));
    for (const marker of ["a.b.test.ck", "www.ck", "b.c.mm", "city.kobe.jp", "食狮.中国"]) {
      expect(inputs, `corpus lost ${marker}`).toContain(marker);
    }
  });

  it("is pinned in lockstep with the tldts release that carries the list", () => {
    expect(DATA_VERSIONS.publicSuffixList).toMatch(/^tldts@\d+\.\d+\.\d+$/);
    expect(SOURCE_URL).toContain("publicsuffix/list");
  });
});

describe("upstream PSL tests.txt — full corpus against analyzeHost()", () => {
  it.each(HOST_VECTORS)("$input -> $expected", ({ input, expected }) => {
    const actual = analyzeHost(input).registrableDomain;
    const declared = LEDGER.get(input);
    if (declared === undefined) {
      expect(actual).toBe(expected);
    } else {
      // A declared divergence must still land on its pinned value…
      expect(actual, `${input} moved within its divergence class`).toBe(declared.linklint);
      // …and must genuinely still differ from upstream, or the ledger is stale.
      expect(actual, `${input} no longer diverges — drop it from LEDGER`).not.toBe(expected);
    }
  });

  it("the ledger is exact: no undeclared divergence, no stale entry", () => {
    const observed = HOST_VECTORS.filter(
      ({ input, expected }) => analyzeHost(input).registrableDomain !== expected,
    ).map(({ input }) => input);
    expect(new Set(observed)).toEqual(new Set(LEDGER.keys()));
  });

  it("reports the conformance rate", () => {
    const exact = HOST_VECTORS.length - LEDGER.size;
    // 71 of 77 host rows match upstream verbatim; the remaining 6 are the two
    // documented classes below. Pinned so a tldts bump that changes the rate
    // fails here instead of surfacing as a scoring change downstream.
    expect(HOST_VECTORS).toHaveLength(77);
    expect(exact).toBe(71);
    expect(exact / HOST_VECTORS.length).toBeGreaterThan(0.92);
  });
});

describe("divergence class 1 — PRIVATE-section suffixes are a boundary choice", () => {
  const rows = inClass("private-section");

  it("covers exactly the uk.com family", () => {
    expect(rows).toHaveLength(4);
    for (const host of rows) expect(host.endsWith("uk.com")).toBe(true);
  });

  // The proof that this is the ICANN/PRIVATE flag and NOT a data defect or a
  // tldts bug: flipping the one option reproduces every upstream expectation.
  it.each(rows)("%s matches upstream exactly under allowPrivateDomains: true", (host) => {
    const upstream = VECTORS.find((v) => v.input === host)?.expected;
    expect(tldtsParse(host, { allowPrivateDomains: true }).domain).toBe(upstream);
  });

  it("linklint's ICANN-only view is the one wired into analyzeHost", () => {
    // github.io is the FR-D-8 case this boundary exists to serve.
    expect(analyzeHost("user.github.io").registrableDomain).toBe("github.io");
  });
});

describe("divergence class 2 — a leading empty label never reaches the PSL layer", () => {
  const rows = inClass("empty-label");

  it("covers exactly the two leading-dot rows", () => {
    expect(rows).toHaveLength(2);
    for (const host of rows) expect(host.startsWith(".")).toBe(true);
  });

  // The proof that this divergence is unreachable: linklint's parser rejects an
  // empty label before any PSL lookup happens, so tldts's leniency is shielded.
  it.each(rows)("inspect() rejects https://%s/ as invalid", (host) => {
    const r = inspect(`https://${host}/`);
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("parse_error");
  });

  it("a single trailing root dot is still accepted (the rule is empty-label, not any-dot)", () => {
    expect(inspect("https://example.com./").status).toBe("ok");
  });
});
