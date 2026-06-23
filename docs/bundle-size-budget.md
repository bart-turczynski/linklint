# Bundle Size Budget

This project keeps generated data in readable TypeScript unless a measured
release-size cost justifies a more compact representation.

## Confusables generated data

Measured on 2026-06-23 from `packages/core` after `pnpm --filter linklint build`
and `npm pack --json --pack-destination /tmp/linklint-pack --cache /tmp/linklint-npm-cache`.

| Artifact | Raw bytes | Gzip bytes | Package share |
|----------|----------:|-----------:|--------------:|
| `packages/core/src/data/confusables.generated.ts` | 77,166 | 7,896 | source only |
| `packages/core/dist/data/confusables.generated.js` | 79,821 | 7,795 | 2.40% unpacked, about 0.56% compressed |
| `packages/core/dist/data/confusables.generated.d.ts` | 341 | 238 | 0.01% unpacked, about 0.02% compressed |
| Emitted generated confusables total | 80,162 | 8,033 | 2.41% unpacked, about 0.58% compressed |

The packed `linklint@0.1.0-dev.0` artifact measured 1,382,782 bytes
compressed and 3,321,498 bytes unpacked. The gzip figures above are standalone
proxies for compressed contribution because npm reports per-file unpacked sizes,
not per-file tarball deltas.

## Compaction threshold

Do not replace `confusables.generated.ts` with a compact representation unless
the emitted generated confusables files exceed either:

- 250 KiB unpacked in the npm package, or
- 25 KiB gzip as a standalone compressed proxy, or
- 5% of the unpacked `linklint` package.

If a future Unicode refresh crosses one of those thresholds, file a follow-up
implementation issue before changing representation. That issue must require
equivalent UTS#39 conformance coverage for the compact form.

Current decision: the emitted generated confusables total is 80,162 bytes
unpacked and about 8,033 bytes gzip, below all thresholds. Keep the readable
generated TypeScript representation.
