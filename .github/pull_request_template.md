## What and why

<!-- What this changes, and the problem it solves. -->

## Verification

<!-- `pnpm check` runs build + typecheck + Vitest + Cucumber — the same chain as CI. -->

- [ ] `pnpm check` passes locally

## Checklist

<!-- Delete any line that does not apply. -->

- [ ] **New or changed detector** — corpus rows added to
      `packages/core/test/corpus/corpus.ts` for both what it must flag and what
      it must not, and the false-positive surface is described above.
- [ ] **New reason code** — registered in `src/schema/reason-codes.ts` and
      documented in `docs/reason-codes.md` (`docs-validation.test.ts` enforces
      this).
- [ ] **Scoring change** — `docs/scoring.md` updated.
- [ ] **`tldts` / `tr46` bump** — followed the procedure in
      [CONTRIBUTING.md](../CONTRIBUTING.md#bumping-the-tldts-or-tr46-pin),
      including `pnpm data:boundary --check` and committing the regenerated
      baseline alongside the pin.
- [ ] **Closes a known miss** — the corresponding entry in
      `packages/core/test/corpus/embarrassment.ts` is promoted from pending to
      an active guard.
