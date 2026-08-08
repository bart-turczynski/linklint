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

## The verify gate

The gate is `pnpm check` — build, typecheck, test, features — across the Node
matrix declared by `engines.node` (24, the floor, and 26, the current line).

**It runs locally, on every push, and that is the primary gate.** The pre-push
hook calls `tools/verify.sh`, which does what a bare `pnpm check` does not:

```sh
tools/verify.sh                # frozen-lockfile install, then the gate on each Node major
tools/verify.sh --no-install   # skip the install step
```

The `pnpm install --frozen-lockfile` catches lockfile drift that a warm
`node_modules` hides, and the matrix walk catches cross-version breakage that
your default `node` cannot see on its own. Node 24 is usually keg-only on
Homebrew (installed, but off `PATH`), so the script resolves each major by path
rather than trusting `node -v`; if a major is missing it says so loudly and
names the `brew install` that fixes it, because a matrix leg that quietly does
not run is not a gate.

**Remote CI is deliberately narrow.** GitLab's shared runners are metered, so
`.gitlab-ci.yml` creates no pipeline at all for an ordinary code push — an
uncreated pipeline is free, whereas a job that merely skips still costs a runner
slot. It builds on:

- changes to `pnpm-lock.yaml`, any `package.json`, `.node-version`,
  `.gitlab-ci.yml`, `tools/verify.sh`, or the pinned-data stamps
  (`versions.ts`, `psl-provenance.ts`)
- release tags
- the schedule (a canary — nothing in the repo changed, so a failure means the
  world moved: a base image, a transitive dep, a registry)
- **Run pipeline** in the UI, any time you want one

So remote runs buy the two things local runs cannot: a genuinely clean resolve
from the lockfile on stock images, and a machine that is not this one. Those are
worth minutes exactly when dependencies move — which is why that is when they
happen.

> **Remote CI is not executing right now** (`LINK-ozgkfjow`). The rules above are
> live and correct — the first push created a pipeline exactly as designed — but
> the namespace is out of shared-runner compute minutes, so both jobs failed with
> `ci_quota_exceeded` without starting. Until that is resolved, `tools/verify.sh`
> is not merely the primary gate, it is the only one. A red pipeline on GitLab
> right now means the quota, not your tree: check `failure_reason` on the job
> before believing it.

Keep local-only planning state in `_scratch/`. Do not commit `_scratch/`, `.fp/`, secrets, dependency folders, build outputs, or generated caches.

## Bumping the `tldts` or `tr46` pin

These two dependencies are **not ordinary dependencies** — they carry the Public
Suffix List and the UTS-46/Unicode tables that linklint's verdicts are computed
from. A patch-level bump can silently redraw a registrable-domain boundary or
move a normalization result. Treat it as a data change, not a version bump.

`pnpm check` already runs all three gates below; this is the order to work in.

> **Dependabot is not the notification any more** (`LINK-rlrdiqhm`). The GitHub
> account is suspended, so no PR will arrive. Ask the registry directly instead:
>
> ```sh
> pnpm data:upstream-check
> ```
>
> It compares every `<name>@<version>` stamp in `DATA_VERSIONS` against the
> registry's `latest` and exits non-zero when one has moved, naming the release
> and its publish date — which is the date `PSL_PROVENANCE.pslListDate` wants.
> Exit `2` means the check could not run (no network, bad answer); that is not a
> pass. Run it before a release and whenever you touch the pins.
>
> It is deliberately **not** in the pre-push hook: `tools/verify.sh` has to work
> offline, and a network call there would turn a plane ride into a failed push.
> It cannot go in a GitLab schedule yet either, for want of runner minutes
> (`LINK-ozgkfjow`) — so for now it is yours to run.
>
> What it still cannot tell you: whether the *list inside* `tldts` moved. That
> needs a bump plus `pnpm data:boundary --check`, below.

**The dependabot PR is a notification, not a merge candidate.** Dependabot opens
one per `tldts`/`tr46` release and it arrives **red**, because it moves the pin
without moving the stamps and `data-versions.test.ts` catches that. That is the
gate working, not a broken PR. Do not merge it and do not "fix CI" on it — do
the procedure below on your own branch, land that, and close the dependabot PR
as superseded.

Keeping these PRs is deliberate, and the reason is that nothing *inside* the
repository can tell us upstream moved. linklint has no network path and never
contacts publicsuffix.org, and `PSL_PROVENANCE.pslListDate` is a
packaging-release **proxy** — it bounds the snapshot's age from below only, so
inside the freshness window `pslOutdated()` returns `null` (undetermined) and
can never say "a new list shipped". The signal has to come from outside, which
is what the dependabot PR was and what `pnpm data:upstream-check` now is. An
`ignore:` entry would buy a quieter PR list at the cost of one of the two
mechanisms that surface a silently ageing trust boundary — the exact failure the
provenance record exists to make visible.

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
