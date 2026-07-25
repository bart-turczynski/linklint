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
