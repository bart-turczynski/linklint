# Bundle Size Budget

This project keeps generated data in readable TypeScript unless a measured
release-size cost justifies a more compact representation.

Every figure on this page is re-measured by
[`packages/core/test/bundle-size-budget.test.ts`](../packages/core/test/bundle-size-budget.test.ts)
on each `pnpm check`, which fails when the prose and the measurement disagree.
The figures here were previously taken by hand and went unmaintained for weeks;
a stale denominator is what retired the third threshold (see below).

## How the figures are produced

- Raw bytes are file sizes after `pnpm --filter linklint build` — plain
  `tsc -p tsconfig.build.json`, no bundler.
- Gzip bytes are `zlib.gzipSync(buf, { level: 9 })`, a **headerless** stream. On
  the command line the equivalent is `gzip -9 -n`; plain `gzip -9` stores the
  source filename in the header and reports a few bytes more, which reads as
  drift that is not there.
- The total gzip figure is the sum of the per-file figures rather than one gzip
  over the concatenation. It is a standalone proxy for compressed contribution,
  because npm reports per-file unpacked sizes and not per-file tarball deltas.

## Confusables generated data

| Artifact | Raw bytes | Gzip bytes |
|----------|----------:|-----------:|
| `packages/core/src/data/confusables.generated.ts` | 77,166 | 7,896 |
| `packages/core/dist/data/confusables.generated.d.ts` | 341 | 238 |
| `packages/core/dist/data/confusables.generated.js` | 79,821 | 7,795 |
| Emitted generated confusables total | 80,162 | 8,033 |

The `src` row is the authored artifact. The two `dist` rows are what ships:
`packages/core/package.json` publishes `files: ["dist", "README.md"]`, so those
are the bytes the thresholds apply to.

## Compaction threshold

Do not replace `confusables.generated.ts` with a compact representation unless
the emitted generated confusables files exceed either:

- 250 KiB (256,000 bytes) unpacked in the npm package, or
- 25 KiB (25,600 bytes) gzip as a standalone compressed proxy.

If a future Unicode refresh crosses one of those thresholds, file a follow-up
implementation issue before changing representation. That issue must require
equivalent UTS#39 conformance coverage for the compact form.

Current decision: the emitted total is 80,162 bytes unpacked — 31.3% of the
unpacked threshold — and 8,033 bytes gzip, 31.4% of the gzip threshold. Both
sit under budget, so keep the readable generated TypeScript representation.

## Retired: the share-of-package axis

A third threshold read "5% of the unpacked `linklint` package". It was recorded
against a package measured once at 3,321,498 bytes unpacked, and no later run
reproduced that figure: on 2026-08-07 `npm pack --dry-run` reported 696,556
bytes for `packages/core`. Against that denominator the same 80,162 confusables
bytes read as 11.5% — over a 5% budget by 2.3x — while the numerator had not
moved by a single byte.

The axis is retired for that reason. A ratio makes an unrelated part of the
package shrinking schedule a data-representation refactor, and its denominator
depends on which workspace is packed and on what `files` lists at the time. The
two absolute axes above are what protect the published package, and both are
asserted on every check. Restoring a ratio axis would require a denominator
pinned as tightly as the numerator is.

## Browser bundle

The published entry point has its own size gate, in the same test: esbuild
bundles `packages/core/dist/index.js` for `platform: "browser"`,
`format: "esm"`, `target: "es2022"`, and the **minified** output is held under
1 MiB (1,048,576 bytes) raw and 256 KiB (262,144 bytes) gzip. Before this the
bundle was asserted only to be non-empty, so a dependency that doubled it went
unreported.

Those thresholds sit at roughly twice the current measurement. They are a drift
alarm for an accidentally-added dependency, not a golden value to re-baseline on
every commit — so the measured bundle bytes are deliberately not quoted here,
where a source edit would date them. Unminified size is not gated either: it
moves with comment and identifier volume inside dependencies, which is noise
rather than shipped weight.
