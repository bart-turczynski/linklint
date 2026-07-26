# LINK-qvsrmrzv — S3: IP ranges generated from the IANA special-purpose registries

## What landed

- **`tools/data/iana-ipv{4,6}-special-registry-1.csv`** — the two pinned
  registry snapshots, committed (2,423 + 2,289 = 4,712 bytes) so the build is
  offline and byte-reproducible.
- **`tools/build-ip-ranges.mjs`** — generator mirroring `build-confusables.mjs`
  (pinned source URL, `--check` drift mode, generated artifact committed, header
  carrying source URLs + license + row counts + a `sha256` per input, exported
  `IP_RANGES_VERSION`). Two departures from that pattern, both deliberate:
  1. **Default mode is offline** (`--fetch` re-downloads). The snapshots are
     committed, so `--check` compares byte-for-byte *including* the sha lines —
     `build-confusables.mjs` has to strip its sha line because its input is
     re-fetched each run.
  2. **`--check` is actually run** by `packages/core/test/ip-ranges.test.ts`.
     `build-confusables.mjs` has had `--check` since E1 and nothing invokes it,
     so that artifact can drift silently. This one cannot.
- **`packages/core/src/data/ip-ranges.generated.ts`** — 26 IPv4 + 25 IPv6 rows,
  sorted by descending prefix length.
- **`packages/core/src/data/ip-ranges.ts`** — hand-written wrapper: the
  multicast overlay + `matchIpv4Range` / `matchIpv6Range` (longest-prefix-match
  by linear scan of the descending-prefix table).
- **`detectors/ip-classification.ts`** — the ~9 IPv4 `if` statements on octets
  and the ~6 IPv6 tests on the FIRST HEXTET are gone, replaced by two table
  lookups. `hextetsOf()` expands the RFC 5952 canonical form into 8 hextets so
  IPv6 matching happens on the real prefix instead of a hextet-rounded
  approximation.
- **`dataVersions.ipRanges`** (`schema/result.ts` type + `data/versions.ts`
  value) = `"iana-special-purpose-2026-07-25"`.
- **Detail now carries the registry citation**, e.g.
  `host '10.0.0.1' resolves to a private (internal) address (10.0.0.1) — IANA
  Private-Use, [RFC1918]`. `IpClassification` gained optional `rangeName` /
  `rangeRfc` (same source-compatible pattern as S2's `provider`).
- Root `package.json`: `data:ip-ranges` script. `tools/README.md` +
  `docs/reason-codes.md`: provenance, the LPM rationale, the curated classes.

## The bucket-mapping judgment

The registry has no loopback/private/link-local taxonomy — only a `Name` and a
set of boolean columns. Mapping is by NAME first, then by `Globally Reachable`:

| Registry name | Bucket |
| --- | --- |
| `Loopback`, `Loopback Address` | `ip_loopback` |
| `Private-Use`, `Unique-Local` | `ip_private` |
| `Link Local`, `Link-Local Unicast` | `ip_link_local` |
| `Documentation…` | **none** (curated) |
| transition wrappers | **none** (curated) |
| anything with `Globally Reachable = True` | **none** |
| everything else (`False`, `N/A`, or blank) | `ip_reserved` |

Four judgment calls sit on top of that mechanical mapping:

1. **`bucket: null` rows are EMITTED, not dropped.** They are what makes
   longest-prefix-match load-bearing: `192.0.0.9/32` and `192.0.0.10/32` are
   globally reachable carve-outs inside non-global `192.0.0.0/24`, and
   `2001:1::1/128` is one inside `2001::/23`. A null bucket at a longer prefix
   STOPS the search rather than falling through to its parent. A flat
   first-match list cannot express this at all — that is the whole reason the
   issue asked for LPM, and both directions are pinned by tests.

2. **Documentation → no bucket** (`192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `2001:db8::/32`, and — a free addition from the registry —
   `3fff::/20`, RFC 9637's newer documentation block). A documentation address
   is inert: not an SSRF target, and naming one is not deception.
   `corpus.ts:449` pins `https://[2001:db8::1]/` at score exactly 0 and
   `precision-recall.test.ts` asserts `falsePositives === 0`.

3. **Transition wrapper prefixes → no bucket.** *(This one is a design fork; it
   is NOT what a literal reading of the registry would produce — see below.)*
   `::ffff:0:0/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2001::/32` (Teredo) and
   `2002::/16` (6to4) are routing envelopes, not destination classes. What
   matters is the IPv4 inside, which S1 already classifies for the low-32
   wrappers. Three of these five have `Globally Reachable = False`/`N/A`, so a
   mechanical mapping would bucket them `ip_reserved` — and that would flip
   three pinned benign corpus rows into false positives
   (`[::ffff:808:808]` IPv4-mapped 8.8.8.8, `[64:ff9b:1::a9fe:a9fe]`,
   `[2002:a9fe:a9fe::]` — all labelled **benign** with
   `forbidReasons: ["ip_reserved", …]` as the S1 precision guards) plus the
   `::ffff:8.8.8.8` and Teredo assertions in `ip-classification.test.ts`
   ("a wrapper around an ORDINARY public IPv4 stays unclassified" and
   "out-of-scope transition prefixes are untouched"). Marking `::ffff:0:0/96`
   reserved is also just
   wrong on the merits: `::ffff:8.8.8.8` *is* 8.8.8.8. Whether the 6to4/Teredo
   envelopes themselves deserve a signal is a question for the unwrapping issue
   (LINK-evooubiz), where the embedded address becomes available; it is not
   decidable from the registry columns.

4. **Multicast is an explicit non-registry overlay.** `224.0.0.0/4` and
   `ff00::/8` are NOT in these registries (they live in the separate IANA
   Multicast Address Space registries — `grep -c '^224\.'` and `grep -c '^ff00'`
   both return 0), but `corpus.ts` pins `239.0.0.1` and `[ff02::1]` as
   `ip_reserved`. They are declared in `data/ip-ranges.ts` with a comment saying
   why, exactly like the cloud-metadata table, and participate in the same
   most-specific match rather than being special-cased.

Also worth recording: the registry is *strictly better* than the hand-rolled
list it replaced. `198.18.0.0/15` (benchmarking), `100::/64` (discard-only),
`5f00::/16` (SRv6 SIDs), `2001::/23`, `192.0.0.0/24`, `192.88.99.0/24` and the
deprecated ORCHID block were all missing before; `240.0.0.0/4` was previously
reached by an `a >= 224` catch-all that conflated multicast with future-use.

## Pins that moved (both deliberate, both reported)

1. **`packages/core/test/ip-classification.test.ts`** — `classify("192.0.0.193")`
   was `[]`, now `["ip_reserved"]`. `192.0.0.0/24` is the IANA *IETF Protocol
   Assignments* block with `Globally Reachable = False`. This is the flip the
   task sanctioned. `192.0.0.192` (Oracle) stays `ip_cloud_metadata` — the /32
   overlay is the most specific match — and `100.100.100.201` → `ip_reserved`
   is unchanged.
2. **`packages/online/test/safe-transport.test.ts`** — `198.18.0.1` was
   categorised `benchmark` (that package's supplemental table), now
   `ip_reserved` (core answers first, because the registry has
   `198.18.0.0/15 Benchmarking, Globally Reachable = False`). The address is
   **blocked either way**; only the label moved. `packages/online/src/` is
   untouched, per scope — its independent table stays for a later unification.
   The `documentation` rows in the same table still fall through to online's
   supplemental rules, because core deliberately leaves documentation prefixes
   unclassified.

## Artifact size (bundle budget)

Budget (`docs/bundle-size-budget.md`): 250 KiB unpacked / 25 KiB gzip / 5% of
the package. Measured after `pnpm build`:

| Artifact | Raw bytes | Gzip bytes |
| --- | ---: | ---: |
| `src/data/ip-ranges.generated.ts` | 10,335 | — (source only) |
| `src/data/ip-ranges.ts` | 4,324 | — (source only) |
| `dist/data/ip-ranges.generated.js` | 9,434 | 2,412 |
| `dist/data/ip-ranges.js` | 3,188 | 1,430 |
| `dist/data/ip-ranges.generated.d.ts` | 1,239 | 508 |
| `dist/data/ip-ranges.d.ts` | 2,501 | 1,216 |
| **Emitted total** | **16,362** | **5,566** |

16,362 bytes unpacked is **0.49%** of the 3,321,498-byte unpacked package and
about 6.5% of the unpacked budget; 5,566 bytes gzip is 22% of the gzip budget.
Below every threshold — keep the readable generated TypeScript. The two
committed CSVs (4,712 bytes) are build inputs under `tools/`, not shipped in the
package.

## Verification

`pnpm check` exit 0 — `Test Files 103 passed` (baseline 102 + the new
`ip-ranges.test.ts`), `Tests 2079 passed` (baseline 2049 + 30), `51 scenarios`,
`215 steps`. Perf gate: mean `inspect()` 0.0363 ms, worst single call 0.1115 ms
(bound: 5 ms) — a ~26-row scan per family with no BigInt anywhere.

Drift guard verified by hand in both directions: `--check` exits 0 on the
committed artifact, exits 1 after a one-line edit, and exits 0 again after
regeneration; `--input-v4/--input-v6` reproduces the same bytes from an
arbitrary copy of the CSVs.
