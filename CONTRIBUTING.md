# Contributing

This project ships under the [Contributor Covenant](./CODE_OF_CONDUCT.md).
Security vulnerabilities go through the private channel in
[SECURITY.md](./SECURITY.md) — never a public issue. A URL linklint *failed to
flag* is a correctness issue, not a vulnerability; see
[*What linklint does not do*](./README.md#what-linklint-does-not-do) for where
the boundary sits, then open a normal issue.

Install dependencies:

```sh
pnpm install
```

Run verification:

```sh
pnpm check
```

Source lives in `src/`, behavior features live in `features/`, tests live in `tests/`, and durable project context lives in `docs/`.

Keep local-only planning state in `_scratch/`. Do not commit `_scratch/`, `.fp/`, secrets, dependency folders, build outputs, or generated caches.

## Bumping the `tldts` or `tr46` pin

These two dependencies are **not ordinary dependencies** — they carry the Public
Suffix List and the UTS-46/Unicode tables that linklint's verdicts are computed
from. A patch-level bump can silently redraw a registrable-domain boundary or
move a normalization result. Treat it as a data change, not a version bump.

`pnpm check` already runs all three gates below; this is the order to work in.

**The dependabot PR is a notification, not a merge candidate.** Dependabot opens
one per `tldts`/`tr46` release and it arrives **red**, because it moves the pin
without moving the stamps and `data-versions.test.ts` catches that. That is the
gate working, not a broken PR. Do not merge it and do not "fix CI" on it — do
the procedure below on your own branch, land that, and close the dependabot PR
as superseded.

Keeping these PRs is deliberate, and the reason is that nothing else can tell us
upstream moved. linklint has no network path and never contacts
publicsuffix.org, and `PSL_PROVENANCE.pslListDate` is a packaging-release
**proxy** — it bounds the snapshot's age from below only, so inside the freshness
window `pslOutdated()` returns `null` (undetermined) and can never say "a new
list shipped". The dependabot PR is the repository's only automatic signal that
the bundled data changed. An `ignore:` entry would buy a quieter PR list at the
cost of the one mechanism that surfaces a silently ageing trust boundary — the
exact failure the provenance record exists to make visible.

1. **Bump the pin and its stamps together.** Update `DATA_VERSIONS`
   (`src/data/versions.ts`) and, for `tldts`, all three fields of
   `PSL_PROVENANCE` (`src/data/psl-provenance.ts`). `data-versions.test.ts`
   asserts the stamps match the installed versions, and `psl-provenance.test.ts`
   pins the two `tldts` records to each other.

2. **Check the blast radius on linklint's own answers.**

   ```sh
   pnpm data:boundary --check
   ```

   This diffs the committed baseline (currently 264 hosts: the brand watchlist,
   every corpus vector, the upstream PSL corpus, and the IMC '23 multi-tenant eTLDs)
   against what the new pin produces, and reports every host whose registrable
   domain, PSL section, or normalization result moved. **Read the diff.** A
   `SECTION MOVES` entry — a rule crossing the ICANN/PRIVATE boundary — deserves
   particular attention: it changes one boundary view while leaving the other
   intact, so it can shift detector behaviour without any conformance test
   noticing.

   If the change is intended, regenerate and commit the baseline **in the same
   commit as the bump**, so review sees the pin and its consequences together:

   ```sh
   pnpm data:boundary
   ```

3. **Confirm upstream conformance still holds.** `psl-conformance.test.ts` and
   `idna-conformance.test.ts` run the full upstream corpora. A new divergence
   must be triaged as a linklint bug or a documented, justified profile
   difference — recorded in `docs/architecture.md` §6.1/§6.2 and in the test's
   ledger. **Never silently allowlist one.**

   If a bump moves the *Unicode* version behind `tr46` (not just its own
   version), refresh the vendored `IdnaTestV2.txt` to match — see
   `packages/core/test/data/README.md`.
