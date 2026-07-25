# Vendored conformance corpora

Upstream test corpora committed verbatim so the conformance suites run **offline
and deterministically**. These files are test inputs only — they are not imported
by library source and never ship (`packages/core/package.json` publishes `dist`
and `README.md` only), so they do not count against
[`docs/bundle-size-budget.md`](../../../../docs/bundle-size-budget.md).

Each corpus is pinned by `sha256` inside its own test file. Refreshing a snapshot
is a deliberate act: re-download, update the pinned digest, then re-triage the
divergence ledger. A refresh that moves rows without updating the ledger fails
loudly rather than silently re-baselining.

**These files are committed byte-for-byte.** `.pre-commit-config.yaml` excludes
this directory from the `end-of-file-fixer` and `trailing-whitespace` hooks —
`IdnaTestV2.txt` carries trailing whitespace on 7 lines, and letting a hook strip
it would break the pinned digest and the ability to re-verify against the
publisher with a plain `shasum -a 256`. (Same class of hazard as the
`mixed-line-ending` hook corrupting the IANA CSVs during S3; both corpora here are
LF-only, so that hook is a no-op for them.)

## `psl-tests.txt` — Public Suffix List conformance

| | |
|---|---|
| Source | <https://raw.githubusercontent.com/publicsuffix/list/main/tests/tests.txt> |
| Upstream commit | `e6065d27b4ef9bd74b7d430775f2f6233d4ff581` (2016-02-20) |
| Retrieved | 2026-07-25 |
| `sha256` | `61a3a502cf471d1a919d5e43c10e910023b0c4230e1db506f8e2ff0b47d2234e` |
| Bytes | 2320 (LF) |
| Rows | 78 (77 host rows + 1 `null` input row) |
| License | CC0 / public domain (stated in the file header) |
| Consumed by | [`../psl-conformance.test.ts`](../psl-conformance.test.ts) |

The upstream file is the reference `checkPublicSuffix()` vector list. It has been
byte-stable since 2016, so the pin is a tight one. It exercises the **full**
list — ICANN *and* PRIVATE sections — while linklint resolves ICANN-only
(`allowPrivateDomains: false`); that difference is the larger of the two
documented divergence classes and is asserted, not waived.

## `IdnaTestV2.txt` — UTS-46 / IDNA conformance

| | |
|---|---|
| Source | <https://www.unicode.org/Public/idna/latest/IdnaTestV2.txt> |
| Unicode version | **17.0.0** (file header `Date: 2025-05-01`) |
| Retrieved | 2026-07-25 |
| `sha256` | `beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf` |
| Bytes | 775973 (LF) |
| Rows | 6391 |
| License | [Unicode Terms of Use](https://www.unicode.org/terms_of_use.html) (permissive, attribution) |
| Consumed by | [`../idna-conformance.test.ts`](../idna-conformance.test.ts) |

**The source URL is a moving target.** Unicode publishes 17.0's IDNA data under
`idna/latest/` only — there is no `idna/17.0.0/` directory yet (the versioned
tree stops at `16.0.0`), so `latest/` is the sole path that serves it. It will
point at 18.0 when that ships. The vendored bytes plus the pinned `sha256` are
what make this reproducible; the URL is provenance, not a guarantee. Prefer
`https://www.unicode.org/Public/idna/17.0.0/IdnaTestV2.txt` once it exists.

The pinned version is chosen to match the bundled `tr46@6.0.0`, which carries
Unicode 17.0 data — the 16.0 corpus fails 13 rows against it, all at CJK
Extension J code points (`U+323B0..U+3347B`) assigned in 17.0. See
`docs/architecture.md` §6.2.
