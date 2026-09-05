# Data-build tools

Scripts that regenerate version-pinned data tables bundled into `@linklint/core`.
Generated files are committed (they are source the library imports) but must
**never be hand-edited** — re-run the relevant script instead.

> `fp-extensions/` is not a data build — it holds this repo's issue-tracker
> guards, which live here because `.fp/` is gitignored. See
> [`fp-extensions/README.md`](fp-extensions/README.md).

> `check-upstream.ts` is not a data build either — it generates nothing and
> writes nothing. It watches the two data-carrying npm pins for movement. See
> [below](#check-upstreamts--npm-backed-pin-movement).

> `audit-dependencies.ts` is not a data build either, and `audit-exceptions.json`
> is not generated data — it is a hand-maintained policy file, the one file under
> `tools/` that is *supposed* to be edited by hand. See
> [below](#audit-dependenciests--dependency-vulnerability-audit).

## `build-confusables.mjs` — UTS#39 confusables (E1)

Generates `packages/core/src/data/confusables.generated.ts` from the official
[Unicode Security Mechanisms](https://www.unicode.org/reports/tr39) confusables
list.

```bash
# Regenerate from the COMMITTED snapshot (default — offline, deterministic):
node tools/build-confusables.mjs

# Move the pin forward: re-download confusables.txt, then rebuild:
node tools/build-confusables.mjs --fetch

# Parse an arbitrary local copy:
node tools/build-confusables.mjs --input path/to/confusables.txt

# Drift guard — fail if the committed output is stale:
node tools/build-confusables.mjs --check
```

(Also available as `pnpm data:confusables` from the repo root.)

**Offline by default (LINK-hfencvmf).** `confusables.txt` (~706 KB) is committed
under `tools/data/`, so the artifact is reproducible with no network and
`--check` is a real guard. `packages/core/test/confusables-drift.test.ts` runs it
in CI, and additionally asserts that the `sha256` recorded in the generated
header is the digest of the committed snapshot — so swapping the input without
rebuilding fails even if the parsed output happens to be unchanged. Before this,
`--check` existed but needed the network, so nothing ran it and this was the one
generated artifact that could drift silently.

The snapshot is committed **byte-for-byte** (4,654 lines carry trailing
whitespace upstream); `.pre-commit-config.yaml` excludes `tools/data/` from the
whitespace-rewriting hooks so the digest stays verifiable against unicode.org.

**Pinned source.** Unicode **16.0.0**:
`https://www.unicode.org/Public/security/16.0.0/confusables.txt`. The generated
file records the source URL, version, and a `sha256` of the exact bytes parsed,
so any regeneration is verifiable. Bump `UNICODE_VERSION` in the script to move
to a newer release (e.g. 17.0.0) deliberately.

> **Baseline note — the 16.0.0 pin is deliberate, do not "align" it.**
> This pin does not match the IDNA baseline: the bundled `tr46@6.0.0` carries
> **Unicode 17.0** data, established by the U1 conformance run
> (`packages/core/test/idna-conformance.test.ts`). The two data sets are
> independent — confusables drive `confusable_char` and the Latin-skeleton
> homograph check; the IDNA mapping table drives normalization — so the skew is
> not a defect.
>
> Moving confusables to 17.0 was **measured and declined** (`LINK-tydjfmci`).
> 17.0 adds `þ → p` (LATIN SMALL LETTER THORN), so a Latin-script host whose only
> non-ASCII character is `þ` skeletons entirely to ASCII and trips
> `homograph_latin_skeleton` — critical, weight 1.0:
>
> | Host | Unicode 16.0.0 | Unicode 17.0 |
> |---|---|---|
> | `þingvellir.is` (Icelandic UNESCO site) | `info` 0.00 | **`critical` 1.00** |
>
> The full suite passed under the 17.0 table apart from the drift guard — the
> curated corpus contains no Icelandic, so it *confirmed* a bump that breaks real
> browsing. Same self-confirming failure mode recorded after `brand_combosquat`
> (`LINK-cqdrdvfu`). `confusables-drift.test.ts` now carries a tripwire that fails
> on the bump next to the `--check` failure, so the reason travels with it.
>
> To move the pin, first either exclude `þ` from the curated subset or require a
> script change before `homograph_latin_skeleton` may fire. The 17.0 table is
> published at `security/latest/` only (there is no versioned `17.0.0/`
> directory), which is a moving target and a second reason to pin deliberately.

**Curated subset (OQ-1 / NFR-DATA-2/3).** Rather than ship the full ~6,300-row
table, the script filters to the high-risk cross-script subset that drives domain
homographs:

- **source** — a single non-ASCII Letter/Mark/Number (the shape of a character
  that can appear in a host label or path and impersonate ASCII);
- **target** — an all-ASCII-alphanumeric prototype (single letters/digits, plus
  multi-codepoint lookalikes such as `æ → ae` or `rn → m`).

This keeps the default `inspect()` bundle compact (~1,400 entries) while covering
Cyrillic/Greek/fullwidth/mathematical/etc. lookalikes. The annotation is
**informational only** (weight 0, FR-D-15/16): single-script legitimate IDNs
still score 0 (SC-2) because the cross-script de-noiser that actually scores is
`mixed_script`, not raw confusable annotation.

**License.** The confusables data is published under the Unicode Terms of Use
(permissive, attribution) — MIT-compatible to bundle. Attribution is recorded in
the generated file header.

## `build-ip-ranges.mjs` — IANA special-purpose IP ranges (S3)

Generates `packages/core/src/data/ip-ranges.generated.ts` from the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv)
and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv)
Special-Purpose Address Registries.

```bash
# Regenerate from the COMMITTED snapshots (default — offline, deterministic):
node tools/build-ip-ranges.mjs

# Move the pin forward: re-download both registries, then rebuild:
node tools/build-ip-ranges.mjs --fetch

# Parse an arbitrary local copy:
node tools/build-ip-ranges.mjs --input-v4 v4.csv --input-v6 v6.csv

# Drift guard — fail if the committed output is stale:
node tools/build-ip-ranges.mjs --check
```

(Also available as `pnpm data:ip-ranges` from the repo root.)

**Pinned source.** Unlike the confusables script, the default mode is **offline**:
both registry CSVs (~4.7 KB total) are committed under `tools/data/`, so the
artifact is byte-reproducible with no network and `--check` is a real guard.
`packages/core/test/ip-ranges.test.ts` runs `--check` in CI, so the artifact
cannot drift from its inputs unnoticed. `--fetch` is the deliberate act of
refreshing the snapshots; bump `SNAPSHOT_DATE` in the script when you do.

**Parsing notes.** Both registries need a real CSV reader: they contain quoted
fields with **embedded newlines** (multi-RFC citations), a cell holding **two
address blocks** (`"192.0.0.170/32, 192.0.0.171/32"`), and footnote markers that
contaminate values (`192.0.0.0/24 [2]`, `False [1]`, `N/A [3]`).

**Bucket mapping and curation.** The registry has no loopback/private/link-local
taxonomy — only a name plus boolean columns — so the mapping is by name first,
then by `Globally Reachable`. Documentation and transition-wrapper prefixes are
deliberately mapped to **no bucket**, and multicast (not in these registries) is
overlaid in `packages/core/src/data/ip-ranges.ts`. The script header documents
the full mapping and the reasoning.

**License.** IANA registry data is public domain — no restrictions on reuse.
Source URLs, byte counts, row counts, and a `sha256` of each parsed file are
recorded in the generated header.

## `check-upstream.ts` — npm-backed pin movement

Asks the npm registry whether any `<name>@<version>` stamp in `DATA_VERSIONS`
has moved. Reads nothing else and writes nothing.

```bash
# Check every npm-backed data pin, and date any release found:
pnpm data:upstream-check

# Skip the publish-date lookup (see the cost note below):
pnpm data:upstream-check --no-dates
```

Exit codes are three, because "could not check" must not read as "all clear":
`0` every pin matches the registry's `latest`, `1` at least one has moved, `2`
the check could not run — no network, an unparseable answer, or a stamp shaped
like a package the registry does not know.

**Why it exists (`LINK-rlrdiqhm`).** `tldts` and `tr46` carry the Public Suffix
List and the UTS-46 tables that linklint's verdicts are computed from, so a
release of either is a data change, not a version bump. Until 2026-08 the only
automatic signal that one had shipped came from outside the repository, and when
that signal stopped `tldts@7.4.10` slipped past the 7.4.9 pin unnoticed. This
script replaced it, and is now the only such signal — GitLab opens no dependency
PRs, so nothing arrives unasked. Nothing inside the repository can close that gap on its own —
linklint has no network path, and `PSL_PROVENANCE.pslListDate` is a
packaging-release proxy that bounds the snapshot's age from below only, so
`pslOutdated()` reads `null` (undetermined) inside its window rather than
"current".

**It reads the stamps, not the installed tree.** `data-versions.test.ts` already
pins each stamp to the version actually installed, so the stamp *is* the pin and
there is one source of truth rather than two.

**Which packages are watched is derived, not listed.** Any `DATA_VERSIONS` value
shaped `<name>@<version>` is checked, so a stamp added later for a new npm-backed
source comes under the check by being stamped. Dated and curated stamps
(`fileExtensionTlds`, `brands`, `ipRanges`, …) carry no `@` and are skipped — they have
no registry to ask. `tests/unit/check-upstream.test.ts` pins the derived set
against the shipped record.

**Not in the pre-push hook, deliberately.** `tools/verify.sh` is the primary gate
and has to work offline; a network call there would turn a plane ride into a
failed push. A GitLab schedule is the natural second home and is blocked only on
runner minutes (`LINK-ozgkfjow`).

**Cost note.** The `latest` lookup is a few kilobytes per package. The publish
date lives only in the full packument (~3.4 MB for `tldts`), so it is fetched
only for a package that already turned out to have moved, and `--no-dates` skips
it. The date is worth one fetch because it is exactly what
`PSL_PROVENANCE.pslListDate` records.

**What it cannot tell you.** Whether the list *inside* `tldts` moved. A current
pin says nothing about the bundled snapshot's currency; that question needs a
bump plus `pnpm data:boundary --check`, per CONTRIBUTING.md §"Bumping the
`tldts` or `tr46` pin".

## `audit-dependencies.ts` — dependency vulnerability audit

Scans the whole workspace lockfile (production, dev and optional, every
workspace project) against the npm advisory database and applies this
repository's severity policy. Generates nothing.

```bash
pnpm audit:deps
```

Exit codes are three, on the same rule as `check-upstream.ts`: `0` nothing
blocking, `1` at least one high/critical advisory with no live exception, `2` the
audit could not be evaluated — no network, a registry error, an unparseable or
filtered report, or an invalid exception ledger. Moderate, low and info are
listed and never block.

**Why a wrapper and not `pnpm audit --audit-level high` (`LINK-urjaxlrz`).** Two
properties of pnpm 11.8.0, measured rather than read: `--audit-level` *prunes*
the advisory list instead of only setting a threshold, so the below-threshold
findings survive as an aggregate count and nothing more; and exit `1` means both
"found something" and "could not reach the registry" — the failure arrives as
`{"error":{"code":"pnpm","message":"fetch failed"}}` on stdout, with an empty
stderr, so only the shape of stdout distinguishes it. `--ignore-registry-errors`
exists and turns a failed scan into exit `0`, which is the fail-open this check
is built to refuse. The tool therefore reads the full report and decides itself,
and rejects a report that arrives already filtered.

**`audit-exceptions.json` is policy, not generated data.** It is the one file
under `tools/` meant to be hand-edited. Each entry records an advisory, the
module it is accepted for, a reason, an `acceptedOn` and an inclusive `reviewBy`
after which the exception stops suppressing. `pnpm audit --ignore` is never used:
it carries no reason and no expiry. The full field rules are in CONTRIBUTING.md
§"Auditing dependencies for known vulnerabilities".

**Not in the pre-push hook, deliberately** — and for one more reason than
`check-upstream.ts` has. Beyond `tools/verify.sh` needing to work offline, the
gate is expected to be deterministic; the advisory database moves under a tree
that has not, so the same commit would pass and then fail. Run it before a
release and after any dependency change. A GitLab schedule is the natural second
home and is blocked on runner minutes (`LINK-ozgkfjow`, follow-up
`LINK-txxcwplc`).

**What it cannot tell you.** Whether an advisory is *reachable* from linklint's
own code paths. It reports what the resolved tree contains, which is a floor: a
vulnerable transitive package that nothing ever calls still appears, and a
genuine exploit path in a package with no advisory does not.

## `check-release-version.mjs` — tag/manifest agreement gate

Refuses a release whose tag and workspace manifests disagree. Runs as the first
step of the `publish` job in `.gitlab-ci.yml`; there is no pnpm script, because
it is a release gate rather than something to run by hand.

```bash
node tools/check-release-version.mjs v0.1.0
```

Exit codes are three, on the same rule as the two tools above: `0` the tag and
all four packages agree, `1` they do not, `2` the check could not run (no tag
argument, unreadable manifests, no packages found).

**Why it exists (`LINK-geygvedm`).** `pnpm publish` rewrites every `workspace:*`
dependency to the exact version it resolves to, at pack time — measured, not
assumed: packing `@linklint/cli` at `0.1.0-dev.0` yields
`"dependencies": {"linklint": "0.1.0-dev.0"}` inside the tarball. Two failures
follow, and npm versions are immutable, so neither is recoverable after the
fact: a lagging manifest ships a dependent pinned to a `linklint` version that
was never published, and a tag that disagrees with the manifests names a release
the registry does not have.

**Dependency-free on purpose.** Plain ESM on bare `node`, no `tsx`, so it can run
before any install has happened and cannot itself be the thing that breaks a
release. `tests/unit/check-release-version.test.ts` pins the decision, which is
exported separately from the filesystem walk and the `process.exit`.

**What it cannot tell you.** Whether the version is the *right* one — that the
CHANGELOG entry exists, that the bump matches the size of the change, or that
the tag points at the commit you think it does. It checks agreement, not
judgment.
