/**
 * LINK-rlrdiqhm — contract tests for `tools/check-upstream.ts`, the only signal
 * that an npm-backed data pin has moved.
 *
 * EVERY REGISTRY READ IS INJECTED. `pnpm check` runs offline (and runs inside
 * `tools/verify.sh`, which is expected to work on a plane), so nothing here
 * opens a socket. What is pinned is the decision logic: which stamps get
 * watched, how versions are ordered, and — the property the whole tool exists
 * for — that a failed lookup can never be rendered as a clean result.
 *
 * WHAT THIS SUITE CANNOT EXERCISE, stated explicitly per the
 * `enforcement-scripts.test.ts` precedent:
 *   - The npm registry's own responses. That `/<pkg>/latest` carries `version`
 *     and that the full packument carries `time[<version>]` are properties of
 *     the registry; the shapes are pinned here as fixtures, not verified.
 *   - The process exit codes. `main()` is not exported — the exit mapping is
 *     three lines over `state`, and running the real thing to check them would
 *     mean a network call. The `state` values those lines read ARE pinned.
 *   - Whether a reported move is a real upstream data change. Only
 *     `pnpm data:boundary --check` can answer that, and it is the next step the
 *     report tells a human to take.
 */
import { describe, expect, it } from "vitest";
import {
  checkUpstream,
  compareSemver,
  formatReport,
  npmStamps,
  parseSemver,
  type NpmStamp,
  type RegistryClient,
  type StampReport,
} from "../../tools/check-upstream.js";

/** A `DATA_VERSIONS`-shaped record; the real type is closed, fixtures are not. */
function versions(entries: Record<string, string>) {
  return entries as unknown as Parameters<typeof npmStamps>[0];
}

/** A registry whose answers are a lookup table. */
function fakeRegistry(
  latest: Record<string, string>,
  times: Record<string, string> = {},
): RegistryClient {
  return {
    async latestVersion(pkg) {
      const v = latest[pkg];
      if (v === undefined) throw new Error(`no fixture for ${pkg}`);
      return v;
    },
    async publishedAt(pkg, version) {
      return times[`${pkg}@${version}`] ?? null;
    },
  };
}

describe("npmStamps — which DATA_VERSIONS entries get watched", () => {
  it("picks up `<name>@<version>` stamps and ignores dated/curated ones", () => {
    expect(
      npmStamps(
        versions({
          publicSuffixList: "tldts@7.4.9",
          idna: "tr46@6.0.0",
          fileExtensionTlds: "2026-06-19",
          brands: "2026-07-26-watchlist",
          unicodeConfusables: "uts39-16.0.0-curated",
          unicodeScripts: "ecma-unicode-property-escapes",
          weights: "1.17",
        }),
      ),
    ).toEqual([
      { key: "publicSuffixList", pkg: "tldts", pinned: "7.4.9" },
      { key: "idna", pkg: "tr46", pinned: "6.0.0" },
    ]);
  });

  it("splits a scoped package at the LAST @, not the first", () => {
    expect(npmStamps(versions({ x: "@scope/pkg@1.2.3" }))).toEqual([
      { key: "x", pkg: "@scope/pkg", pinned: "1.2.3" },
    ]);
  });

  it("does not read a bare scope or a trailing @ as a pin", () => {
    expect(npmStamps(versions({ a: "@scope/pkg", b: "pkg@", c: "" }))).toEqual([]);
  });

  it("watches every npm-backed stamp the shipped DATA_VERSIONS carries", async () => {
    // The real record, so adding an npm-backed source without it coming under
    // this check is a test failure rather than a silent watch gap.
    const { DATA_VERSIONS } = await import("../../packages/core/src/data/versions.js");
    expect(npmStamps(DATA_VERSIONS).map((s) => s.pkg).sort()).toEqual(["tldts", "tr46"]);
  });
});

describe("compareSemver — release ordering", () => {
  it.each([
    ["7.4.9", "7.4.10", -1],
    ["7.4.10", "7.4.9", 1],
    ["7.4.9", "7.4.9", 0],
    ["6.0.0", "10.0.0", -1],
    ["1.2.3", "1.10.0", -1],
  ])("orders %s against %s", (a, b, sign) => {
    expect(Math.sign(compareSemver(a, b))).toBe(sign);
  });

  it("sorts a prerelease BELOW the release sharing its core", () => {
    // The reason this matters: a maintainer publishing 7.5.0-beta.1 to `latest`
    // must not make a stable 7.4.10 pin report as behind a stable release.
    expect(Math.sign(compareSemver("7.5.0", "7.5.0-beta.1"))).toBe(1);
    expect(Math.sign(compareSemver("7.4.10", "7.5.0-beta.1"))).toBe(-1);
  });

  it("orders prerelease identifiers numerically, then lexically, then by length", () => {
    expect(Math.sign(compareSemver("1.0.0-alpha.2", "1.0.0-alpha.10"))).toBe(-1);
    expect(Math.sign(compareSemver("1.0.0-alpha", "1.0.0-beta"))).toBe(-1);
    expect(Math.sign(compareSemver("1.0.0-alpha", "1.0.0-alpha.1"))).toBe(-1);
    expect(Math.sign(compareSemver("1.0.0-1", "1.0.0-alpha"))).toBe(-1);
  });

  it("ignores build metadata", () => {
    expect(compareSemver("1.0.0+abc", "1.0.0+xyz")).toBe(0);
  });

  it("throws rather than guessing an order for a non-semver version", () => {
    expect(parseSemver("not-a-version")).toBeNull();
    expect(() => compareSemver("1.0", "1.0.0")).toThrow(/not a semver/);
  });
});

const TLDTS: NpmStamp = { key: "publicSuffixList", pkg: "tldts", pinned: "7.4.9" };
const TR46: NpmStamp = { key: "idna", pkg: "tr46", pinned: "6.0.0" };

describe("checkUpstream — verdicts", () => {
  it("reports a moved pin as behind and dates the release", async () => {
    const reports = await checkUpstream([TLDTS], fakeRegistry({ tldts: "7.4.10" }, {
      "tldts@7.4.10": "2026-07-30T23:11:08.153Z",
    }));
    expect(reports).toEqual([
      { ...TLDTS, latest: "7.4.10", state: "behind", publishedAt: "2026-07-30T23:11:08.153Z" },
    ]);
  });

  it("reports a matching pin as current and does not spend a packument fetch on it", async () => {
    let dated = 0;
    const client: RegistryClient = {
      async latestVersion() {
        return "6.0.0";
      },
      async publishedAt() {
        dated += 1;
        return null;
      },
    };
    const reports = await checkUpstream([TR46], client);
    expect(reports[0]?.state).toBe("current");
    expect(dated).toBe(0);
  });

  it("skips the date lookup under --no-dates", async () => {
    let dated = 0;
    const client: RegistryClient = {
      async latestVersion() {
        return "7.4.10";
      },
      async publishedAt() {
        dated += 1;
        return null;
      },
    };
    const reports = await checkUpstream([TLDTS], client, { dates: false });
    expect(reports[0]?.state).toBe("behind");
    expect(reports[0]?.publishedAt).toBeNull();
    expect(dated).toBe(0);
  });

  it("reports a pin ahead of the dist-tag rather than calling it current", async () => {
    // Happens after an unpublish or a dist-tag rollback. It is not "fine".
    const reports = await checkUpstream([TLDTS], fakeRegistry({ tldts: "7.4.8" }));
    expect(reports[0]?.state).toBe("ahead");
  });

  it("rejects when a lookup fails — a broken check is never a clean check", async () => {
    const client: RegistryClient = {
      async latestVersion() {
        throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
      },
      async publishedAt() {
        return null;
      },
    };
    await expect(checkUpstream([TLDTS], client)).rejects.toThrow(/ENOTFOUND/);
  });

  it("rejects when the registry answers with a version it cannot order", async () => {
    await expect(checkUpstream([TLDTS], fakeRegistry({ tldts: "latest" }))).rejects.toThrow(
      /not a semver/,
    );
  });
});

describe("formatReport", () => {
  const behind: StampReport = {
    ...TLDTS,
    latest: "7.4.10",
    state: "behind",
    publishedAt: "2026-07-30T23:11:08.153Z",
  };
  const current: StampReport = { ...TR46, latest: "6.0.0", state: "current", publishedAt: null };

  it("names the moved package and routes the reader to the data-change procedure", () => {
    const out = formatReport([behind, current]);
    expect(out).toMatch(/BEHIND \(published 2026-07-30\)/);
    expect(out).toMatch(/1 data pin no longer matches upstream: tldts\./);
    expect(out).toMatch(/CONTRIBUTING\.md/);
    expect(out).toMatch(/data:boundary --check/);
  });

  it("says so plainly when nothing moved", () => {
    expect(formatReport([current])).toMatch(/Every npm-backed data pin matches/);
  });

  it("pluralizes over the moved set", () => {
    const two = formatReport([behind, { ...current, latest: "6.1.0", state: "behind" }]);
    expect(two).toMatch(/2 data pins no longer match upstream: tldts, tr46\./);
  });
});
