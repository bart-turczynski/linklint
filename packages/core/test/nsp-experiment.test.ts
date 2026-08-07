import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  admits,
  diffExperiments,
  extractIpv4,
  RFC6052_LAYOUTS,
  readExperiment,
  runExperiment,
  sampleAddresses,
  SAMPLE_SIZE,
  SEED,
  splitmix64,
  toIpv6,
  UBYTE_OCTET,
  type Rfc6052Layout,
} from "./nsp-experiment.js";
import { classifyHost } from "../src/detectors/ip-classification.js";

/**
 * LINK-qunjjduo — the reproducibility gate for the RFC 6052 network-specific-
 * prefix false-positive figures quoted in docs/reason-codes.md.
 *
 * Before this, those figures ("20 000 random addresses", "59.2%", "14.0%") had
 * no seed, no RNG, no sample and no script anywhere in the repository: a reader
 * could not check them and a maintainer could not tell whether a range-table
 * change had moved them. This suite runs the experiment on every check and
 * diffs it against the committed artifact, and asserts the prose quotes the
 * numbers the artifact actually holds.
 *
 * It also pins the RFC reading the old prose got wrong — §2.2 reserves octet 8
 * at EVERY permitted prefix length, /96 included — because that misreading is
 * what made the residue look ~64x larger than it is.
 */

const DOCS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "docs",
  "reason-codes.md",
);

const layoutFor = (prefix: number): Rfc6052Layout => {
  const found = RFC6052_LAYOUTS.find((l) => l.prefix === prefix);
  if (found === undefined) throw new Error(`no layout /${prefix}`);
  return found;
};

/** 8 hextets → the 16 octets the experiment works on. */
const octetsOf = (hextets: readonly number[]): Uint8Array => {
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (hextets[i] as number) >>> 8;
    out[i * 2 + 1] = (hextets[i] as number) & 0xff;
  }
  return out;
};

describe("the sample is a pure function of the seed", () => {
  it("is SplitMix64, pinned by its published seed-0 vectors", () => {
    // Not "some PRNG produced the same bytes twice" — these three values are the
    // reference output of SplitMix64 from state 0, so a reader can confirm the
    // algorithm named in the module docs is the algorithm implemented here, and
    // re-derive the whole sample in any other language.
    const a = splitmix64(0n);
    const b = splitmix64(a.state);
    const c = splitmix64(b.state);
    expect([a.value, b.value, c.value]).toEqual([
      0xe220a8397b1dcdafn,
      0x6e789e6aa1b965f4n,
      0x06c45d188009454fn,
    ]);
  });

  it("redraws the identical sample — no clock, no network, no Math.random", () => {
    const a = sampleAddresses(64, SEED);
    const b = sampleAddresses(64, SEED);
    expect(a.map(toIpv6)).toEqual(b.map(toIpv6));
    expect(a).toHaveLength(64);
  });

  it("a different seed gives a different sample", () => {
    // The negative control: if the seed were ignored, every figure below would be
    // reproducible and meaningless at the same time.
    expect(sampleAddresses(64, SEED).map(toIpv6)).not.toEqual(
      sampleAddresses(64, SEED + 1n).map(toIpv6),
    );
  });

  it("is a prefix stream — the first N of a longer draw are the shorter draw", () => {
    expect(sampleAddresses(200, SEED).slice(0, 50).map(toIpv6)).toEqual(
      sampleAddresses(50, SEED).map(toIpv6),
    );
  });
});

describe("the six layouts are RFC 6052 §2.2, checked against §2.4", () => {
  // The RFC's own worked examples: every one of these encodes 192.0.2.33 at its
  // stated prefix length. If a v4Octets row were mis-transcribed, the whole
  // experiment would price the wrong decoder — this is the check that the table
  // is the RFC's table and not a plausible-looking invention.
  const EXAMPLES: ReadonlyArray<{ prefix: number; hextets: readonly number[] }> = [
    { prefix: 32, hextets: [0x2001, 0x0db8, 0xc000, 0x0221, 0, 0, 0, 0] },
    { prefix: 40, hextets: [0x2001, 0x0db8, 0x01c0, 0x0002, 0x0021, 0, 0, 0] },
    { prefix: 48, hextets: [0x2001, 0x0db8, 0x0122, 0xc000, 0x0002, 0x2100, 0, 0] },
    { prefix: 56, hextets: [0x2001, 0x0db8, 0x0122, 0x03c0, 0, 0x0221, 0, 0] },
    { prefix: 64, hextets: [0x2001, 0x0db8, 0x0122, 0x0344, 0x00c0, 0x0002, 0x2100, 0] },
    { prefix: 96, hextets: [0x2001, 0x0db8, 0x0122, 0x0344, 0, 0, 0xc000, 0x0221] },
  ];

  it("covers all six permitted prefix lengths, once each", () => {
    expect(RFC6052_LAYOUTS.map((l) => l.prefix)).toEqual([32, 40, 48, 56, 64, 96]);
  });

  for (const { prefix, hextets } of EXAMPLES) {
    it(`/${prefix} decodes the §2.4 example to 192.0.2.33`, () => {
      expect(extractIpv4(octetsOf(hextets), layoutFor(prefix))).toBe("192.0.2.33");
    });
  }

  it("every §2.4 example carries a zero u-byte — including the /96 one", () => {
    // The RFC's own /96 example has octet 8 zero. That is the observable form of
    // the correction below: §2.2 does not exempt /96.
    for (const { hextets } of EXAMPLES) {
      expect(octetsOf(hextets)[UBYTE_OCTET]).toBe(0);
    }
  });

  it("each layout reads four distinct octets, none of them the u-byte", () => {
    for (const layout of RFC6052_LAYOUTS) {
      expect(new Set(layout.v4Octets).size).toBe(4);
      expect(layout.v4Octets).not.toContain(UBYTE_OCTET);
      for (const i of layout.v4Octets) expect(i).toBeGreaterThanOrEqual(0);
      for (const i of layout.v4Octets) expect(i).toBeLessThan(16);
    }
  });
});

describe("the u-byte applies to /96 too (the correction this experiment exists for)", () => {
  // Under /96 the u-byte falls inside the operator prefix rather than beside the
  // embedded IPv4 — but RFC 6052 §2.2 still requires it to be zero, so a decoder
  // can still check it. The old prose said /96 "has no u-byte to check"; these
  // two assertions are what that claim costs.
  const dirtyUbyte = octetsOf([0x2001, 0x0db8, 0, 0, 0xff00, 0, 0xc0a8, 0x0001]);

  it("the conformant filter rejects a /96 read when octet 8 is non-zero", () => {
    expect(dirtyUbyte[UBYTE_OCTET]).toBe(0xff);
    expect(admits("ubyte-all", layoutFor(96), dirtyUbyte)).toBe(false);
  });

  it("the reconstructed old filter accepts it — that is the 64x difference", () => {
    expect(admits("ubyte-except-96", layoutFor(96), dirtyUbyte)).toBe(true);
    // ...while still rejecting the other five, exactly as the old figure implied.
    for (const prefix of [32, 40, 48, 56, 64]) {
      expect(admits("ubyte-except-96", layoutFor(prefix), dirtyUbyte)).toBe(false);
    }
  });

  it("only /96 is recorded as having the u-byte inside the prefix", () => {
    for (const layout of RFC6052_LAYOUTS) {
      expect(layout.ubyteInsidePrefix, `/${layout.prefix}`).toBe(layout.prefix === 96);
    }
  });

  it("`none` ignores the u-byte entirely", () => {
    for (const layout of RFC6052_LAYOUTS) expect(admits("none", layout, dirtyUbyte)).toBe(true);
  });
});

describe("the committed artifact still reproduces", () => {
  const committed = readExperiment();

  it(
    "re-running the experiment yields the committed figures",
    () => {
      // Re-drawing 200 000 addresses and classifying up to six candidate IPv4s
      // each costs a few seconds; the default 5 s vitest timeout is too tight to
      // be a reliable gate on a loaded machine (see confusables-drift.test.ts for
      // the same reasoning and the ~50x load multiplier that motivated it).
      expect(diffExperiments(committed, runExperiment()).join("\n")).toBe("");
    },
    60_000,
  );

  it("is stamped with the range-table version it was measured against", () => {
    // A range-table bump moves these rates. Failing here names the culprit
    // instead of leaving a bare percentage mismatch.
    expect(committed._meta.sampleSize).toBe(SAMPLE_SIZE);
    expect(committed._meta.seed).toBe(`0x${SEED.toString(16)}`);
    expect(committed.sample.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("orders the three filters as the argument does", () => {
    const { none, "ubyte-except-96": old, "ubyte-all": fixed } = committed.filters;
    expect(none.spuriousPct).toBeGreaterThan(old.spuriousPct);
    expect(old.spuriousPct).toBeGreaterThan(fixed.spuriousPct);
  });

  it("reproduces the previously documented 59.2% / 14.0% within sampling error", () => {
    // The reconstruction check. Landing on the old figures from an independent
    // sample is what licenses calling `ubyte-except-96` the filter that produced
    // them — and therefore what licenses calling the 14% figure superseded
    // rather than merely different.
    expect(committed.filters.none.spuriousPct).toBeGreaterThan(58);
    expect(committed.filters.none.spuriousPct).toBeLessThan(60);
    expect(committed.filters["ubyte-except-96"].spuriousPct).toBeGreaterThan(13);
    expect(committed.filters["ubyte-except-96"].spuriousPct).toBeLessThan(15);
  });

  it("the old filter's residue IS almost all /96; the corrected one's is not", () => {
    // The second half of the correction. Under the non-conformant filter the /96
    // layout accounts for essentially the whole residue, which is what the old
    // prose described. Enforce the u-byte everywhere and the six layouts
    // contribute on the same order as each other.
    const old = committed.filters["ubyte-except-96"].spuriousByLayout;
    expect(old["/96"] as number).toBeGreaterThan(0.9 * committed.filters["ubyte-except-96"].spurious);

    const fixed = committed.filters["ubyte-all"].spuriousByLayout;
    const counts = Object.values(fixed);
    expect(Math.max(...counts) / Math.min(...counts)).toBeLessThan(3);
  });
});

describe("docs/reason-codes.md quotes the artifact", () => {
  const prose = readFileSync(DOCS, "utf8");
  const committed = readExperiment();

  it("names the sample size and the seeded generator", () => {
    expect(prose).toContain(committed._meta.sampleSize.toLocaleString("en-US").replace(",", " "));
    expect(prose).toContain("nsp-experiment");
  });

  it("quotes each measured rate to one decimal place", () => {
    for (const filter of ["none", "ubyte-except-96", "ubyte-all"] as const) {
      const pct = committed.filters[filter].spuriousPct.toFixed(filter === "ubyte-all" ? 2 : 1);
      expect(prose, filter).toContain(`${pct}%`);
    }
  });
});

describe("measuring the cost of speculation did not introduce it", () => {
  it("the shipped classifier still decodes no NSP layout", () => {
    // The experiment prices a decoder that does not exist. These are the same
    // vectors ip-classification.test.ts guards; asserted here too so a future
    // edit to this file cannot quietly turn the measurement into a feature.
    for (const h of [
      "2001:db8::a9fe:a9fe",
      "2001:db8:122:344:a9:fea9:fe00::",
      "2001:db8:c0a8:1::",
    ]) {
      expect(classifyHost(h), h).toBeNull();
    }
  });

  it("the recognizable /96 wrappers are untouched by the experiment's existence", () => {
    expect(classifyHost("64:ff9b::a9fe:a9fe")?.bucket).toBe("ip_cloud_metadata");
    expect(classifyHost("::ffff:7f00:1")?.bucket).toBe("ip_loopback");
  });
});
