# Data-build tools

Scripts that regenerate version-pinned data tables bundled into `@linklint/core`.
Generated files are committed (they are source the library imports) but must
**never be hand-edited** — re-run the relevant script instead.

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
