/**
 * Boundary-diff gate for `tldts` / `tr46` pin bumps (LINK-jwnqtase / U3).
 *
 *   pnpm data:boundary            # regenerate test/data/boundary-baseline.json
 *   pnpm data:boundary --check    # print what MOVED, exit 1 if anything did
 *
 * This lives under `test/` rather than `tools/` for a mechanical reason: pnpm's
 * strict layout resolves `tldts` from `packages/core`, not the repo root, and the
 * PRIVATE-inclusive view below needs it directly. It is a fixture module, not a
 * suite — `boundary-baseline.test.ts` is what runs on every check.
 *
 * WHY THIS EXISTS, given U1 and U2 already run full upstream corpora: those
 * answer "does linklint still agree with upstream?". They do NOT answer the
 * question that actually matters at bump time — "did this bump move an answer
 * for a host linklint reasons about?". A change can be perfectly conformant
 * upstream (a genuinely new PSL rule, a newly-assigned code point) and still
 * silently redraw a brand's registrable domain. pslr built `psl_diff`
 * (PSLR-ayahzscr) for exactly this after surveying PSL libraries across ten
 * language ecosystems and finding none that offered snapshot-to-snapshot diffing.
 *
 * WHAT IT DOES. Records linklint's OWN answers — not upstream's — for a fixed
 * input set, and diffs them against the committed baseline. The output is a
 * reviewable list of what changed, so a human sees the blast radius before the
 * bump merges. `--check` additionally exits non-zero, so an unreviewed bump
 * cannot land quietly; `boundary-baseline.test.ts` runs it on every check.
 *
 * The recorded view per host is deliberately wider than what `inspect()` uses:
 *
 *   - the ICANN-only view (`analyzeHost`, what linklint actually reasons with)
 *   - the PRIVATE-inclusive view, and `isIcann` — WHICH SECTION the matching rule
 *     came from. A rule migrating between the ICANN and PRIVATE sections is a
 *     distinct, reviewable event: it moves the boundary for one view without
 *     touching the other, and would otherwise be invisible here.
 *   - both normalization results (transitional and nontransitional) plus the
 *     U-label, since `tr46` owns all three.
 *
 * OFFLINE AND DETERMINISTIC. Every input is committed (brand watchlist, corpus
 * vectors, the vendored PSL corpus); no clock, no network, no ordering
 * dependence. Re-running without a dependency change is a no-op.
 */
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as tldtsParse } from "tldts";
import { BRAND_DOMAINS } from "../src/data/brands.js";
import { DATA_VERSIONS } from "../src/data/versions.js";
import { deriveHostFacts } from "../src/parse/host-facts.js";
import { parse } from "../src/parse/parse.js";
import { toAsciiUnder } from "../src/unicode/idna.js";
import { VECTORS } from "./corpus/vectors.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const BASELINE_PATH = join(HERE, "data", "boundary-baseline.json");
const PSL_CORPUS = join(HERE, "data", "psl-tests.txt");

/**
 * IMC '23 (McQuistin et al., Table 2) multi-tenant eTLDs, plus a tenant under
 * each. These live in the PSL PRIVATE section, so they are the hosts most likely
 * to move sections on a bump — and the ones `freshness-corpus.test.ts` guards.
 * Kept explicit here (that file holds them as local consts) so the input set is
 * self-describing; the baseline test asserts they are all present.
 */
const MULTI_TENANT_ETLDS = [
  "myshopify.com",
  "readthedocs.io",
  "netlify.app",
  "web.app",
  "carrd.co",
  "digitaloceanspaces.com",
  "r.appspot.com",
  "github.io",
  "blogspot.com",
  "vercel.app",
] as const;

/** One host's full boundary + normalization answer. */
export interface BoundaryRow {
  /** ICANN-only registrable domain — the view `inspect()` reasons with. */
  readonly icannDomain: string | null;
  readonly icannSuffix: string | null;
  readonly icannSubdomain: string | null;
  /** PRIVATE-inclusive registrable domain (the freshness-gated view). */
  readonly privateDomain: string | null;
  readonly privateSuffix: string | null;
  /** Which PSL section the matching rule came from; `null` when no rule matched. */
  readonly isIcann: boolean | null;
  readonly isIp: boolean;
  /** U-label form (`xn--` decoded) — drives confusable / script analysis. */
  readonly unicode: string;
  /** toASCII, nontransitional (IDNA2008) and transitional (IDNA2003). */
  readonly asciiN: string | null;
  readonly asciiT: string | null;
}

export interface Baseline {
  readonly _meta: {
    readonly note: string;
    readonly publicSuffixList: string;
    readonly idna: string;
    readonly hosts: number;
  };
  readonly hosts: Readonly<Record<string, BoundaryRow>>;
}

/**
 * The fixed input set: every host linklint has an opinion about, drawn only from
 * committed sources. Sorted and de-duplicated so the artifact is stable.
 */
export function collectHosts(): string[] {
  const hosts = new Set<string>();

  // 1. The brand watchlist — the most bump-sensitive detector surface, since
  //    brand matching compares whole registrable domains.
  for (const domain of BRAND_DOMAINS) hosts.add(domain);

  // 2. Every corpus vector, via linklint's OWN parser (preserves U-labels, which
  //    `new URL().hostname` would silently punycode away).
  for (const vector of VECTORS) {
    const host = parse(vector.input)?.host;
    if (host !== undefined && host !== "") hosts.add(host);
  }

  // 3. The vendored upstream PSL corpus — every rule shape upstream tests.
  for (const raw of readFileSync(PSL_CORPUS, "utf8").split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("//")) continue;
    const input = line.split(/\s+/)[0];
    if (input !== undefined && input !== "null") hosts.add(input);
  }

  // 4. Multi-tenant eTLDs and a tenant under each (section-move candidates).
  for (const etld of MULTI_TENANT_ETLDS) {
    hosts.add(etld);
    hosts.add(`tenant.${etld}`);
  }

  return [...hosts].sort();
}

/** Linklint's complete answer for one host. */
export function rowFor(host: string): BoundaryRow {
  const facts = deriveHostFacts(host);
  const priv = tldtsParse(host, { allowPrivateDomains: true, detectIp: true });
  return {
    icannDomain: facts.psl.registrableDomain,
    icannSuffix: facts.psl.publicSuffix,
    icannSubdomain: facts.psl.subdomain,
    privateDomain: priv.domain,
    privateSuffix: priv.publicSuffix,
    isIcann: priv.isIcann,
    isIp: facts.isIp,
    unicode: facts.hostUnicode,
    asciiN: toAsciiUnder(host, false),
    asciiT: toAsciiUnder(host, true),
  };
}

export function buildBaseline(): Baseline {
  const hosts: Record<string, BoundaryRow> = {};
  const list = collectHosts();
  for (const host of list) hosts[host] = rowFor(host);
  return {
    _meta: {
      note: "AUTO-GENERATED by packages/core/test/boundary-baseline.ts — regenerate with `pnpm data:boundary`. Do NOT hand-edit.",
      publicSuffixList: DATA_VERSIONS.publicSuffixList,
      idna: DATA_VERSIONS.idna,
      hosts: list.length,
    },
    hosts,
  };
}

export function readBaseline(): Baseline {
  return JSON.parse(readFileSync(BASELINE_PATH, "utf8")) as Baseline;
}

/** Stable, diff-friendly rendering: sorted keys, one host block per entry. */
export function render(baseline: Baseline): string {
  return `${JSON.stringify(baseline, null, 2)}\n`;
}

const FIELD_LABELS: Record<keyof BoundaryRow, string> = {
  icannDomain: "registrable domain (ICANN-only)",
  icannSuffix: "public suffix (ICANN-only)",
  icannSubdomain: "subdomain (ICANN-only)",
  privateDomain: "registrable domain (PRIVATE-inclusive)",
  privateSuffix: "public suffix (PRIVATE-inclusive)",
  isIcann: "PSL SECTION",
  isIp: "is-IP",
  unicode: "U-label",
  asciiN: "toASCII nontransitional",
  asciiT: "toASCII transitional",
};

/**
 * Human-readable diff. Section moves are called out first and separately: they
 * are the class that changes one boundary view while leaving the other intact.
 */
export function diffBaselines(before: Baseline, after: Baseline): string[] {
  const lines: string[] = [];

  if (before._meta.publicSuffixList !== after._meta.publicSuffixList) {
    lines.push(`PIN  tldts: ${before._meta.publicSuffixList} -> ${after._meta.publicSuffixList}`);
  }
  if (before._meta.idna !== after._meta.idna) {
    lines.push(`PIN  tr46:  ${before._meta.idna} -> ${after._meta.idna}`);
  }

  const hosts = [...new Set([...Object.keys(before.hosts), ...Object.keys(after.hosts)])].sort();
  const sectionMoves: string[] = [];
  const changes: string[] = [];

  for (const host of hosts) {
    const a = before.hosts[host];
    const b = after.hosts[host];
    if (a === undefined) {
      changes.push(`ADDED    ${host}`);
      continue;
    }
    if (b === undefined) {
      changes.push(`REMOVED  ${host}`);
      continue;
    }
    for (const key of Object.keys(FIELD_LABELS) as (keyof BoundaryRow)[]) {
      if (a[key] === b[key]) continue;
      const line = `  ${host}: ${FIELD_LABELS[key]}: ${JSON.stringify(a[key])} -> ${JSON.stringify(b[key])}`;
      if (key === "isIcann") sectionMoves.push(line);
      else changes.push(line);
    }
  }

  if (sectionMoves.length > 0) {
    lines.push(`SECTION MOVES (${sectionMoves.length}) — a rule crossed the ICANN/PRIVATE boundary:`);
    lines.push(...sectionMoves);
  }
  if (changes.length > 0) {
    lines.push(`CHANGED ANSWERS (${changes.length}):`);
    lines.push(...changes);
  }
  return lines;
}

// ── CLI ──────────────────────────────────────────────────────────────────────
// Guarded so importing this module from a test does not run the CLI.
const entrypoint = process.argv[1];
if (entrypoint !== undefined && realpathSync(entrypoint) === fileURLToPath(import.meta.url)) {
  const checkOnly = process.argv.includes("--check");
  const current = buildBaseline();

  if (checkOnly) {
    const lines = diffBaselines(readBaseline(), current);
    if (lines.length > 0) {
      process.stderr.write(
        "Boundary answers MOVED since the committed baseline.\n\n" +
          `${lines.join("\n")}\n\n` +
          "Review the blast radius above. If it is intended, re-run `pnpm data:boundary`\n" +
          "and commit the refreshed baseline IN THE SAME COMMIT as the pin bump.\n",
      );
      process.exit(1);
    }
    process.stderr.write(`OK — ${current._meta.hosts} hosts unchanged.\n`);
  } else {
    writeFileSync(BASELINE_PATH, render(current));
    process.stderr.write(`Wrote ${current._meta.hosts} hosts to ${BASELINE_PATH}\n`);
  }
}
