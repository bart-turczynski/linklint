/**
 * `pnpm data:upstream-check` — asks the npm registry whether any npm-backed
 * stamp in `DATA_VERSIONS` has moved (LINK-rlrdiqhm).
 *
 * WHY THIS EXISTS. `tldts` and `tr46` carry the Public Suffix List and the
 * UTS-46 tables that linklint's verdicts are computed from, so a release of
 * either is a data change (CONTRIBUTING.md §"Bumping the `tldts` or `tr46`
 * pin"). Until 2026-08 the only automatic signal that one had shipped came from
 * outside the repository; when that signal stopped, `tldts@7.4.10` slipped past
 * unnoticed. This tool is its replacement, and the only one — GitLab opens no
 * dependency PRs, so nothing arrives unasked. Nothing else in the repository
 * can report the move either: linklint has no network path, and
 * `PSL_PROVENANCE.pslListDate` is a packaging-release proxy that bounds the
 * snapshot's age from BELOW only — inside the freshness window `pslOutdated()`
 * returns `null`, which is "undetermined", not "current".
 *
 * WHAT IT COMPARES. The stamps in `DATA_VERSIONS`, not the installed tree.
 * `data-versions.test.ts` already pins each `<name>@<version>` stamp to the
 * version actually installed, so the stamp is the pin, and reading it here
 * keeps one source of truth instead of re-deriving a second one.
 *
 * WHICH PACKAGES. Every stamp whose value is shaped `<name>@<version>`. That is
 * deliberate: a stamp added later for a new npm-backed data source comes under
 * this check by being stamped, with no list here to keep in sync. Stamps that
 * name a date or a curated snapshot (`fileExtensionTlds`, `brands`, `ipRanges`, …)
 * carry no `@` and are skipped — they have no registry to ask.
 *
 * WHAT IT DOES NOT DO.
 *   - It does not check publicsuffix.org. A current `tldts` pin still says
 *     nothing about whether the list bundled inside it is current; the bundled
 *     snapshot is regenerated at that package's build time and is dated only by
 *     proxy. This closes the "upstream *package* moved" gap, and no other.
 *   - It does not bump anything. A move is reported for a human to run the
 *     CONTRIBUTING procedure against, because the bump is a data change whose
 *     blast radius has to be read (`pnpm data:boundary --check`).
 *
 * NEVER PUT THIS IN THE PRE-PUSH HOOK. `tools/verify.sh` is the primary gate
 * and it is expected to work on a plane; a network call there would turn an
 * offline push into a failure. This is a deliberate, separately-invoked check.
 *
 * EXIT CODES — three, because "could not check" must never read as "all clear":
 *   0  every npm-backed stamp matches the registry's `latest`
 *   1  at least one stamp is behind (or ahead of) `latest`
 *   2  the check could not run: no network, a bad registry answer, or a stamp
 *      shaped like a package that the registry does not know
 *
 * Usage:
 *   pnpm data:upstream-check              # check, and date any move found
 *   pnpm data:upstream-check --no-dates   # skip the publish-date lookup
 */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DATA_VERSIONS } from "../packages/core/src/data/versions.js";
import type { DataVersions } from "../packages/core/src/schema/types.js";

/** Default npm registry. Overridden in tests via {@link RegistryClient}. */
const REGISTRY = "https://registry.npmjs.org";

/** Per-request network timeout. */
const TIMEOUT_MS = 15_000;

/** An npm-backed version stamp read out of `DATA_VERSIONS`. */
export interface NpmStamp {
  /** The `DATA_VERSIONS` key the stamp came from, e.g. `publicSuffixList`. */
  key: string;
  /** Package name, e.g. `tldts`. */
  pkg: string;
  /** Pinned version, e.g. `7.4.9`. */
  pinned: string;
}

/**
 * Extract the npm-backed stamps from a `DATA_VERSIONS` record: those whose
 * value splits at the LAST `@` into a non-empty name and a non-empty version.
 *
 * Splitting at the last `@` is what keeps scoped packages (`@scope/pkg@1.2.3`)
 * working. A leading `@` with no second one is a scope with no version, which is
 * not a pin, so it is not a stamp.
 */
export function npmStamps(versions: DataVersions): NpmStamp[] {
  const stamps: NpmStamp[] = [];
  for (const [key, value] of Object.entries(versions)) {
    const at = value.lastIndexOf("@");
    if (at <= 0) continue;
    const pkg = value.slice(0, at);
    const pinned = value.slice(at + 1);
    if (pinned.length === 0) continue;
    stamps.push({ key, pkg, pinned });
  }
  return stamps;
}

interface ParsedSemver {
  core: [number, number, number];
  /** Dot-separated prerelease identifiers; empty for a release. */
  pre: string[];
}

/** Parse `X.Y.Z[-pre][+build]`, or `null` when it is not a semver. */
export function parseSemver(version: string): ParsedSemver | null {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version);
  if (m === null) return null;
  return {
    core: [Number(m[1]), Number(m[2]), Number(m[3])],
    pre: m[4] === undefined ? [] : m[4].split("."),
  };
}

/** Compare two prerelease identifiers per semver §11: numeric < alphanumeric. */
function comparePreIdentifier(a: string, b: string): number {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) return Number(a) - Number(b);
  if (aNum) return -1;
  if (bNum) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Semver precedence: negative when `a` sorts before `b`, positive when after,
 * zero when equal. Build metadata is ignored, and a prerelease sorts BELOW the
 * release that shares its core — so a `7.5.0-beta.1` on `latest` is not read as
 * the 7.4.10 pin being behind a stable release.
 *
 * Throws on an unparseable input rather than guessing an order; the caller
 * turns that into exit code 2.
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (pa === null) throw new Error(`not a semver version: ${a}`);
  if (pb === null) throw new Error(`not a semver version: ${b}`);

  for (let i = 0; i < 3; i++) {
    const diff = (pa.core[i] as number) - (pb.core[i] as number);
    if (diff !== 0) return diff;
  }

  // Equal cores: a release outranks any prerelease of the same core.
  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;

  const shared = Math.min(pa.pre.length, pb.pre.length);
  for (let i = 0; i < shared; i++) {
    const diff = comparePreIdentifier(pa.pre[i] as string, pb.pre[i] as string);
    if (diff !== 0) return diff;
  }
  // All shared identifiers equal: the shorter set has lower precedence.
  return pa.pre.length - pb.pre.length;
}

/** How a stamp stands against the registry's `latest` dist-tag. */
export type StampState = "current" | "behind" | "ahead";

/** One package's verdict. */
export interface StampReport extends NpmStamp {
  latest: string;
  state: StampState;
  /** ISO timestamp `latest` was published, when it was looked up. */
  publishedAt: string | null;
}

/** The registry reads this check needs. Injected so tests never touch a socket. */
export interface RegistryClient {
  /** The version behind the `latest` dist-tag. */
  latestVersion(pkg: string): Promise<string>;
  /** When `version` was published, or `null` when the registry does not say. */
  publishedAt(pkg: string, version: string): Promise<string | null>;
}

async function getJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`${url} responded ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * The live npm registry.
 *
 * `latestVersion` reads `/<pkg>/latest`, a few kilobytes. `publishedAt` reads
 * the FULL packument, which is megabytes for a package with a long release
 * history (`tldts` is ~3.4 MB), because the per-version `time` map lives
 * nowhere lighter. It is therefore called only for a package that already
 * turned out to have moved — and `--no-dates` skips it entirely.
 */
export function npmRegistry(registry: string = REGISTRY): RegistryClient {
  return {
    async latestVersion(pkg) {
      const body = await getJson(`${registry}/${encodeURIComponent(pkg)}/latest`);
      const version = (body as { version?: unknown }).version;
      if (typeof version !== "string") {
        throw new Error(`${pkg}: registry returned no version for the latest dist-tag`);
      }
      return version;
    },
    async publishedAt(pkg, version) {
      const body = await getJson(`${registry}/${encodeURIComponent(pkg)}`);
      const time = (body as { time?: Record<string, unknown> }).time;
      const stamp = time?.[version];
      return typeof stamp === "string" ? stamp : null;
    },
  };
}

/**
 * Compare every npm-backed stamp against the registry. Rejects (→ exit 2) when
 * a lookup fails or an answer is unparseable, so a broken check is never
 * reported as a clean one.
 */
export async function checkUpstream(
  stamps: readonly NpmStamp[],
  client: RegistryClient,
  opts: { dates?: boolean } = {},
): Promise<StampReport[]> {
  const { dates = true } = opts;
  const reports: StampReport[] = [];
  for (const stamp of stamps) {
    const latest = await client.latestVersion(stamp.pkg);
    const order = compareSemver(stamp.pinned, latest);
    const state: StampState = order === 0 ? "current" : order < 0 ? "behind" : "ahead";
    const publishedAt =
      state === "behind" && dates ? await client.publishedAt(stamp.pkg, latest) : null;
    reports.push({ ...stamp, latest, state, publishedAt });
  }
  return reports;
}

/** Render the report block, one line per package plus a verdict. */
export function formatReport(reports: readonly StampReport[]): string {
  const pkgWidth = Math.max(0, ...reports.map((r) => r.pkg.length));
  const pinWidth = Math.max(0, ...reports.map((r) => r.pinned.length));
  const latestWidth = Math.max(0, ...reports.map((r) => r.latest.length));
  const lines = reports.map((r) => {
    const head =
      `  ${r.pkg.padEnd(pkgWidth)}  pinned ${r.pinned.padEnd(pinWidth)}` +
      `  latest ${r.latest.padEnd(latestWidth)}  `;
    if (r.state === "current") return `${head}current`;
    if (r.state === "ahead") return `${head}AHEAD of the latest dist-tag`;
    const when = r.publishedAt === null ? "" : ` (published ${r.publishedAt.slice(0, 10)})`;
    return `${head}BEHIND${when}`;
  });

  const moved = reports.filter((r) => r.state !== "current");
  if (moved.length === 0) {
    lines.push("", "Every npm-backed data pin matches the registry's latest release.");
    return lines.join("\n");
  }

  const subject = moved.length === 1 ? "1 data pin no longer matches" : `${moved.length} data pins no longer match`;
  lines.push(
    "",
    `${subject} upstream: ${moved.map((r) => r.pkg).join(", ")}.`,
    "These pins carry the Public Suffix List and the UTS-46 tables, so a bump is a",
    'data change, not a version bump. Follow CONTRIBUTING.md §"Bumping the `tldts`',
    'or `tr46` pin" — stamps and provenance move with the pin, and',
    "`pnpm data:boundary --check` reports what the new pin does to linklint's own answers.",
  );
  return lines.join("\n");
}

async function main(argv: readonly string[]): Promise<number> {
  const dates = !argv.includes("--no-dates");
  const stamps = npmStamps(DATA_VERSIONS);
  if (stamps.length === 0) {
    process.stderr.write(
      "No npm-backed stamps found in DATA_VERSIONS. Either every data source is now\n" +
        "curated, or a stamp format changed and this check has silently stopped watching.\n",
    );
    return 2;
  }

  process.stdout.write(
    `Checking ${stamps.length} npm-backed DATA_VERSIONS stamp(s) against ${REGISTRY}.\n\n`,
  );

  let reports: StampReport[];
  try {
    reports = await checkUpstream(stamps, npmRegistry(), { dates });
  } catch (error) {
    process.stderr.write(`Could not complete the upstream check: ${String(error)}\n`);
    process.stderr.write("Nothing was verified — this is not a clean result.\n");
    return 2;
  }

  process.stdout.write(`${formatReport(reports)}\n`);
  return reports.some((r) => r.state !== "current") ? 1 : 0;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && realpathSync(invokedPath) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = await main(process.argv.slice(2));
}
