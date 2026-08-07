/**
 * RFC 6052 network-specific-prefix (NSP) false-positive experiment
 * (LINK-qunjjduo, backing the decline recorded in docs/reason-codes.md).
 *
 *   pnpm data:nsp            # regenerate test/data/nsp-experiment.json
 *   pnpm data:nsp --check    # print what MOVED, exit 1 if anything did
 *
 * This lives under `test/` rather than `tools/` for the same mechanical reason
 * as `boundary-baseline.ts`: pnpm's strict layout resolves dependencies from
 * `packages/core`, not the repo root, and the measurement below calls
 * `classifyHost` from `../src` directly. It is a fixture module, not a suite —
 * `nsp-experiment.test.ts` is what runs on every check.
 *
 * WHY THIS EXISTS. docs/reason-codes.md declines speculative NSP decoding partly
 * on a measured false-positive rate. Those figures were quoted with no seed, no
 * RNG, no sample and no script anywhere in the repository, so no reader could
 * reproduce or audit them — and one of the two rates rested on a misreading of
 * RFC 6052 §2.2 (see FILTERS below). This module makes every quantitative claim
 * in that paragraph reproducible from a `git clone`.
 *
 * WHAT IT MEASURES. Draw N pseudo-random 128-bit addresses. For each, ask what a
 * speculative decoder would do: try the six RFC 6052 §2.2 layouts, extract the
 * candidate IPv4 each one implies, and hand the address a range bucket if any
 * candidate lands in one. An address that carries NO bucket today but WOULD
 * carry one under speculation is a false positive attributable purely to the
 * speculation. Buckets come from `classifyHost` — linklint's own classifier, not
 * a re-implementation — so the rate tracks the shipped range table.
 *
 * FILTERS. RFC 6052 §2.2 reserves bits 64-71 (octet 8, the "u-byte") and
 * requires them to be zero in EVERY permitted prefix length. The three filters
 * below differ only in how much of that they enforce:
 *
 *   - `none`             every layout tried on every address; the u-byte ignored.
 *   - `ubyte-except-96`  the u-byte enforced for /32../64 but NOT for /96.
 *                        This is not conformant — it is the reconstruction of
 *                        the filter behind the previously documented 14% figure,
 *                        kept so the correction is auditable rather than
 *                        asserted.
 *   - `ubyte-all`        the u-byte enforced for all six lengths, per §2.2.
 *                        For /96 the u-byte sits INSIDE the operator prefix
 *                        rather than straddling the embedded IPv4, but it is a
 *                        checkable constraint there just the same.
 *
 * OFFLINE AND DETERMINISTIC. The address sample comes from a seeded SplitMix64
 * (see `splitmix64`), never `Math.random`; no clock, no network, no ordering
 * dependence. The artifact records a SHA-256 of the rendered sample, so changing
 * the PRNG, the seed or the sample size fails `--check` by name instead of
 * silently re-baselining the figures.
 *
 * WHAT IT DOES NOT DO. It defines no decoder and changes no behaviour.
 * `parse/ip.ts` still refuses every NSP layout; this module only prices what
 * accepting them would cost.
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyHost } from "../src/detectors/ip-classification.js";
import { DATA_VERSIONS } from "../src/data/versions.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const EXPERIMENT_PATH = join(HERE, "data", "nsp-experiment.json");

// ── Parameters ───────────────────────────────────────────────────────────────

/**
 * Sample size. Sized for the SMALLEST rate being reported: the conformant
 * `ubyte-all` filter fires on roughly 1 address in 430, so 20 000 draws would
 * put ~46 events behind the headline figure (~15% relative error) — enough to
 * make the correction look like noise. 200 000 puts ~460 behind it (~5%), which
 * is tight enough to quote to one decimal place, and still runs in a couple of
 * seconds inside `pnpm check`.
 */
export const SAMPLE_SIZE = 200_000;

/**
 * PRNG seed, chosen to be self-describing rather than lucky: `0x6052` is the RFC
 * number. Any 64-bit value would do; this one is written down so the sample is
 * re-derivable from the two constants in this file alone.
 */
export const SEED = 0x6052n;

// ── PRNG: SplitMix64 ─────────────────────────────────────────────────────────

const MASK64 = (1n << 64n) - 1n;

/**
 * SplitMix64 (Steele, Lea & Flood, OOPSLA '14), the reference algorithm used as
 * the seeding generator for xoshiro/xoroshiro. Chosen because it is four lines
 * of arithmetic with no lookup tables, so this file IS the specification — a
 * reader can re-derive the sample in any language without trusting a dependency.
 *
 * `state` is advanced by the golden-ratio odd constant, then the advanced state
 * is passed through a fixed mixing function. Returns both, so callers thread the
 * state explicitly and the stream stays a pure function of {@link SEED}.
 */
export function splitmix64(state: bigint): { state: bigint; value: bigint } {
  const next = (state + 0x9e3779b97f4a7c15n) & MASK64;
  let z = next;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  z = (z ^ (z >> 31n)) & MASK64;
  return { state: next, value: z };
}

/**
 * The address sample: `count` uniform 128-bit values, two SplitMix64 draws each
 * (high 64 bits then low), rendered as 16 octets. Uniform over the WHOLE address
 * space on purpose — the question is what a decoder does with an arbitrary IPv6
 * literal it has been handed, not what it does with routed traffic.
 */
export function sampleAddresses(count: number, seed: bigint): Uint8Array[] {
  const out: Uint8Array[] = [];
  let state = seed;
  for (let i = 0; i < count; i++) {
    const octets = new Uint8Array(16);
    for (let half = 0; half < 2; half++) {
      const drawn = splitmix64(state);
      state = drawn.state;
      let v = drawn.value;
      for (let b = 7; b >= 0; b--) {
        octets[half * 8 + b] = Number(v & 0xffn);
        v >>= 8n;
      }
    }
    out.push(octets);
  }
  return out;
}

// ── RFC 6052 §2.2 layouts ────────────────────────────────────────────────────

/**
 * The six permitted prefix lengths, each naming the octet indices that carry the
 * embedded IPv4. Read straight off RFC 6052 §2.2 Figure 1: the address is split
 * at the reserved u-byte (octet 8), so every layout shorter than /96 puts part
 * of the IPv4 before it and the rest after, and /64 puts the whole thing after.
 *
 * `ubyteInsidePrefix` records the fact the old prose got wrong. For /96 the
 * u-byte does not straddle the embedded IPv4 — it falls inside the operator
 * prefix — but §2.2 still requires it to be zero, so it remains checkable.
 */
export interface Rfc6052Layout {
  /** Prefix length in bits. */
  readonly prefix: 32 | 40 | 48 | 56 | 64 | 96;
  /** Octet indices, most significant first, holding the embedded IPv4. */
  readonly v4Octets: readonly [number, number, number, number];
  /** True when octet 8 lies within the operator prefix rather than beside the IPv4. */
  readonly ubyteInsidePrefix: boolean;
}

export const RFC6052_LAYOUTS: readonly Rfc6052Layout[] = [
  { prefix: 32, v4Octets: [4, 5, 6, 7], ubyteInsidePrefix: false },
  { prefix: 40, v4Octets: [5, 6, 7, 9], ubyteInsidePrefix: false },
  { prefix: 48, v4Octets: [6, 7, 9, 10], ubyteInsidePrefix: false },
  { prefix: 56, v4Octets: [7, 9, 10, 11], ubyteInsidePrefix: false },
  { prefix: 64, v4Octets: [9, 10, 11, 12], ubyteInsidePrefix: false },
  { prefix: 96, v4Octets: [12, 13, 14, 15], ubyteInsidePrefix: true },
];

/** Octet index of the RFC 6052 §2.2 reserved u-byte (bits 64-71). */
export const UBYTE_OCTET = 8;

/** The embedded IPv4 `a.b.c.d` a given layout would read out of an address. */
export function extractIpv4(octets: Uint8Array, layout: Rfc6052Layout): string {
  return layout.v4Octets.map((i) => octets[i]).join(".");
}

// ── Filters ──────────────────────────────────────────────────────────────────

export type FilterId = "none" | "ubyte-except-96" | "ubyte-all";

export const FILTER_IDS: readonly FilterId[] = ["none", "ubyte-except-96", "ubyte-all"];

export const FILTER_DESCRIPTIONS: Readonly<Record<FilterId, string>> = {
  none: "every layout tried; the RFC 6052 §2.2 reserved u-byte (octet 8) ignored",
  "ubyte-except-96":
    "u-byte enforced for /32,/40,/48,/56,/64 and NOT for /96 — non-conformant; the reconstruction of the previously documented figure",
  "ubyte-all": "u-byte enforced for all six lengths, as RFC 6052 §2.2 requires",
};

/** Would `filter` let a decoder try `layout` on this address? */
export function admits(filter: FilterId, layout: Rfc6052Layout, octets: Uint8Array): boolean {
  if (filter === "none") return true;
  if (filter === "ubyte-except-96" && layout.ubyteInsidePrefix) return true;
  return octets[UBYTE_OCTET] === 0;
}

// ── Measurement ──────────────────────────────────────────────────────────────

/** Render 16 octets as a bare (unbracketed) IPv6 literal, 8 hex groups. */
export function toIpv6(octets: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((((octets[i] as number) << 8) | (octets[i + 1] as number)).toString(16));
  }
  return groups.join(":");
}

export interface FilterResult {
  readonly description: string;
  /** Addresses where at least one admitted layout decoded into a range bucket. */
  readonly bucketed: number;
  /** Of those, the ones that carry no bucket today — the false positives. */
  readonly spurious: number;
  /** `spurious / addressesWithoutBucketToday`, as a percentage to 3 decimals. */
  readonly spuriousPct: number;
  /** Per-layout attribution: how many spurious addresses each layout accounts for. */
  readonly spuriousByLayout: Readonly<Record<string, number>>;
}

export interface Experiment {
  readonly _meta: {
    readonly note: string;
    readonly rfc: string;
    readonly prng: string;
    readonly seed: string;
    readonly sampleSize: number;
    readonly ipRanges: string;
  };
  readonly sample: {
    /** SHA-256 of the newline-joined rendered sample — the input fingerprint. */
    readonly sha256: string;
    /** Addresses linklint already buckets today, without any speculation. */
    readonly bucketedToday: number;
    /** The denominator for every `spuriousPct` below. */
    readonly unbucketedToday: number;
  };
  readonly filters: Readonly<Record<FilterId, FilterResult>>;
}

export function runExperiment(): Experiment {
  const sample = sampleAddresses(SAMPLE_SIZE, SEED);
  const literals = sample.map(toIpv6);

  // Today's answer per address, from the shipped classifier. Computed once and
  // reused as the baseline for all three filters.
  const bucketToday = literals.map((h) => classifyHost(h) !== null);
  const bucketedToday = bucketToday.filter(Boolean).length;
  const unbucketedToday = SAMPLE_SIZE - bucketedToday;

  // Memoized so the ~1.2M candidate decodes collapse onto the 2^32 lookup only
  // where they differ; the sample reuses low-entropy octets constantly.
  const v4Cache = new Map<string, boolean>();
  const v4Buckets = (dotted: string): boolean => {
    let hit = v4Cache.get(dotted);
    if (hit === undefined) {
      hit = classifyHost(dotted) !== null;
      v4Cache.set(dotted, hit);
    }
    return hit;
  };

  const filters = {} as Record<FilterId, FilterResult>;
  for (const filter of FILTER_IDS) {
    let bucketed = 0;
    let spurious = 0;
    const byLayout: Record<string, number> = {};
    for (const layout of RFC6052_LAYOUTS) byLayout[`/${layout.prefix}`] = 0;

    for (let i = 0; i < sample.length; i++) {
      const octets = sample[i] as Uint8Array;
      const already = bucketToday[i] === true;
      let any = false;
      for (const layout of RFC6052_LAYOUTS) {
        if (!admits(filter, layout, octets)) continue;
        if (!v4Buckets(extractIpv4(octets, layout))) continue;
        any = true;
        if (!already) byLayout[`/${layout.prefix}`] = (byLayout[`/${layout.prefix}`] ?? 0) + 1;
      }
      if (!any) continue;
      bucketed++;
      if (!already) spurious++;
    }

    filters[filter] = {
      description: FILTER_DESCRIPTIONS[filter],
      bucketed,
      spurious,
      spuriousPct: Number(((spurious / unbucketedToday) * 100).toFixed(3)),
      spuriousByLayout: byLayout,
    };
  }

  return {
    _meta: {
      note: "AUTO-GENERATED by packages/core/test/nsp-experiment.ts — regenerate with `pnpm data:nsp`. Do NOT hand-edit.",
      rfc: "RFC 6052 §2.2 — six permitted prefix lengths; bits 64-71 (octet 8) reserved and zero at every length",
      prng: "SplitMix64, two draws per address (high 64 bits then low)",
      seed: `0x${SEED.toString(16)}`,
      sampleSize: SAMPLE_SIZE,
      ipRanges: DATA_VERSIONS.ipRanges,
    },
    sample: {
      sha256: createHash("sha256").update(literals.join("\n")).digest("hex"),
      bucketedToday,
      unbucketedToday,
    },
    filters,
  };
}

export function readExperiment(): Experiment {
  return JSON.parse(readFileSync(EXPERIMENT_PATH, "utf8")) as Experiment;
}

export function render(experiment: Experiment): string {
  return `${JSON.stringify(experiment, null, 2)}\n`;
}

/** Human-readable diff, so a failure reads as a review list not an object dump. */
export function diffExperiments(before: Experiment, after: Experiment): string[] {
  const lines: string[] = [];
  const cmp = (label: string, a: unknown, b: unknown): void => {
    if (a !== b) lines.push(`  ${label}: ${JSON.stringify(a)} -> ${JSON.stringify(b)}`);
  };

  cmp("sample seed", before._meta.seed, after._meta.seed);
  cmp("sample size", before._meta.sampleSize, after._meta.sampleSize);
  cmp("PRNG", before._meta.prng, after._meta.prng);
  cmp("sample sha256", before.sample.sha256, after.sample.sha256);
  cmp("IANA range table", before._meta.ipRanges, after._meta.ipRanges);
  cmp("bucketed today", before.sample.bucketedToday, after.sample.bucketedToday);

  for (const filter of FILTER_IDS) {
    const a = before.filters[filter];
    const b = after.filters[filter];
    if (a === undefined || b === undefined) {
      lines.push(`  filter ${filter}: ${a === undefined ? "ADDED" : "REMOVED"}`);
      continue;
    }
    cmp(`${filter}: spurious`, a.spurious, b.spurious);
    cmp(`${filter}: spurious %`, a.spuriousPct, b.spuriousPct);
    cmp(`${filter}: bucketed`, a.bucketed, b.bucketed);
    for (const key of Object.keys(a.spuriousByLayout)) {
      cmp(`${filter}: ${key}`, a.spuriousByLayout[key], b.spuriousByLayout[key]);
    }
  }
  return lines;
}

// ── CLI ──────────────────────────────────────────────────────────────────────
// Guarded so importing this module from a test does not run the CLI.
const entrypoint = process.argv[1];
if (entrypoint !== undefined && realpathSync(entrypoint) === fileURLToPath(import.meta.url)) {
  const checkOnly = process.argv.includes("--check");
  const current = runExperiment();

  if (checkOnly) {
    const lines = diffExperiments(readExperiment(), current);
    if (lines.length > 0) {
      process.stderr.write(
        "NSP experiment results MOVED since the committed artifact.\n\n" +
          `${lines.join("\n")}\n\n` +
          "docs/reason-codes.md quotes these figures. If the move is intended, re-run\n" +
          "`pnpm data:nsp`, update the prose, and commit both IN THE SAME COMMIT.\n",
      );
      process.exit(1);
    }
    process.stderr.write(`OK — ${current._meta.sampleSize} addresses, results unchanged.\n`);
  } else {
    writeFileSync(EXPERIMENT_PATH, render(current));
    for (const filter of FILTER_IDS) {
      const r = current.filters[filter];
      process.stderr.write(`${filter.padEnd(16)} spurious ${r.spurious} (${r.spuriousPct}%)\n`);
    }
    process.stderr.write(`Wrote ${EXPERIMENT_PATH}\n`);
  }
}
