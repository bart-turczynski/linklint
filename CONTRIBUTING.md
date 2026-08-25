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

## Auditing dependencies for known vulnerabilities

```sh
pnpm audit:deps
```

Scans the whole workspace lockfile — production, dev and optional, every
workspace project — against the npm advisory database, and applies this
repository's policy to what comes back:

- **high and critical fail it.** Exit `1`, with the package, the GHSA id, the
  patched range and the path it is reached through.
- **moderate, low and info are reported and do not block.** They are listed, not
  counted: which package, which advisory, which fix.
- **exit `2` means the audit could not be evaluated** — no network, a registry
  error, an unparseable or filtered report, or an invalid exception ledger.
  That is not a pass. Same rule as `pnpm data:upstream-check` above.

**It is deliberately not in `pnpm check` and not in `tools/verify.sh`,** for the
same reason `pnpm data:upstream-check` is not: the gate has to work offline, and
a network call in the pre-push hook turns a plane ride into a failed push. There
is a second reason here. The gate is expected to be deterministic — the same
tree gives the same answer — and an advisory database changes under a tree that
has not moved, so wiring this in would mean a green push and a red one on
identical source. It is a separately-invoked check: **run it before a release and
after any dependency change**, which is exactly when the lockfile can have picked
up something new.

It cannot go in a GitLab schedule yet either, for want of runner minutes
(`LINK-ozgkfjow`); that follow-up is `LINK-txxcwplc`. Until then it is yours to
run.

### Why it is a wrapper and not `pnpm audit --audit-level high`

Two measured properties of pnpm 11.8.0, both recorded at the top of
`tools/audit-dependencies.ts` with the commands that produced them:

1. **`--audit-level` prunes the report rather than only setting a threshold.**
   It deletes every advisory below the threshold from the output while leaving
   `metadata.vulnerabilities` intact, so "report moderate and low" survives the
   flag only as an aggregate number. pnpm's own help says "only *print*
   advisories with severity greater than or equal to".
2. **Exit `1` means both "found something" and "could not ask".** With an
   unreachable registry, `pnpm audit --json` exits `1` with an empty stderr and
   `{"error":{"code":"pnpm","message":"fetch failed"}}` on stdout. Only the shape
   of stdout separates a failed scan from a real finding, so something has to
   read stdout. `--ignore-registry-errors` exists and does the opposite of what
   is wanted: it turns a failed scan into exit `0`.

So the wrapper runs `pnpm audit --json` with no `--audit-level` and applies the
severity policy itself. It also **refuses a report that was filtered before it
arrived** — if `metadata` counts a severity the advisory list does not carry at
all, that is exit `2` rather than a quiet under-report.

### Accepting a risk: the exception ledger

`pnpm audit --ignore GHSA-…` is a silent ignore — no reason, no date, no expiry,
living in a command line nobody reads. It is not used here. Accepted risk goes in
[`tools/audit-exceptions.json`](./tools/audit-exceptions.json):

```json
{
  "exceptions": [
    {
      "advisory": "GHSA-xxxx-xxxx-xxxx",
      "module": "some-package",
      "reason": "Why this is accepted, in enough words to be an argument.",
      "acceptedOn": "2026-08-25",
      "reviewBy": "2026-11-01"
    }
  ]
}
```

- **`reviewBy` is inclusive.** On that date the exception stops suppressing and
  the advisory blocks again. Extending one is a deliberate edit with a fresh
  reason, not a bump.
- **`module` is checked against the advisory.** A copy-pasted entry naming a
  different package fails rather than suppressing something nobody read.
- **`reason` has a length floor.** "TODO" is a silent ignore wearing a ledger's
  clothes.
- **A malformed ledger is exit `2`,** not a skipped entry: an unreadable policy
  is not a pass.
- An entry matching no advisory in the current report is printed as stale and
  should be deleted. It does not fail the command — a dependency being fixed
  upstream is good news.

The ledger ships empty. Accepting a known-vulnerable dependency is a maintainer
decision, and none are pre-made.

`tests/unit/audit-dependencies.test.ts` pins all of the above against fixtures
transcribed from a real run. Nothing in that suite opens a socket, so the offline
gate stays offline and an advisory being published or withdrawn cannot move a
test result.

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
