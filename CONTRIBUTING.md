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

> **Remote CI executes again, and it is not the same machine as yours**
> (`LINK-ozgkfjow`). Between 2026-08 and 2026-09-05 every job failed with
> `ci_quota_exceeded` without starting, and the habit that grew around that — a
> red pipeline means the quota, not your tree — is now wrong. Making the project
> public restored the allowance: pipeline `2822652495` put both matrix legs on
> shared runners.
>
> Read `failure_reason` before drawing either conclusion. `ci_quota_exceeded` is
> the quota; `script_failure` is your tree, and it can be your tree *while
> `tools/verify.sh` is green*, because the runner differs from this workstation
> in ways the local gate cannot simulate — it is Linux rather than macOS, and it
> runs as **root**, so a test that proves a fail-open by making a file unwritable
> does not (`LINK-ujbttpph`).

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

A GitLab schedule is its natural second home, and as of 2026-09-05 runner
minutes no longer block that (`LINK-ozgkfjow`); the follow-up that would set one
up is `LINK-txxcwplc`. Until it exists, this is yours to run.

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

> **Ask the registry; nothing will tell you** (`LINK-rlrdiqhm`). GitLab is the
> only forge this project uses and it opens no dependency PRs, so no upstream
> release announces itself. Ask the registry directly:
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
> A GitLab schedule is its natural second home, and runner minutes no longer
> block that (`LINK-ozgkfjow`) — but none is configured, so for now it is yours
> to run.
>
> What it still cannot tell you: whether the *list inside* `tldts` moved. That
> needs a bump plus `pnpm data:boundary --check`, below.

**A bare pin bump is a notification, not a merge candidate.** Moving `tldts` or
`tr46` without moving the stamps fails `data-versions.test.ts`. That is the gate
working, not a broken change — do the procedure below on your own branch rather
than shipping the bump alone.

The reason an outside signal is needed at all is that nothing *inside* the
repository can tell us upstream moved. linklint has no network path and never
contacts publicsuffix.org, and `PSL_PROVENANCE.pslListDate` is a
packaging-release **proxy** — it bounds the snapshot's age from below only, so
inside the freshness window `pslOutdated()` returns `null` (undetermined) and
can never say "a new list shipped". `pnpm data:upstream-check` is that outside
signal, and it is the only one: run it, or a silently ageing trust boundary goes
unnoticed — the exact failure the provenance record exists to make visible.

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

## Releasing to npm

Publishing runs on GitLab CI, on a tag, and nowhere else. There is no supported
way to publish from a workstation — see *Why CI publishes* below.

### Cutting a release

1. Run the checks that are deliberately outside the pre-push gate, because both
   need a network and the gate does not: `pnpm data:upstream-check` (§*Bumping
   the `tldts` or `tr46` pin*) and `pnpm audit:deps` (§*Auditing dependencies for
   known vulnerabilities*).
2. Move all four `packages/*/package.json` versions **together**, and land the
   `CHANGELOG.md` entry in the same slice.
3. Merge to `main`, then tag it `v<version>` and push the tag. The tag is what
   creates the pipeline: `workflow:rules` admits `$CI_COMMIT_TAG`
   unconditionally, `verify` runs on every Node major in the matrix, and
   `publish` runs only after all of it passes.

**The four versions must be identical.** `pnpm publish` rewrites each
`workspace:*` dependency to the exact version it resolves to at pack time — a
`@linklint/cli` packed at `0.1.0-dev.0` carries `"linklint": "0.1.0-dev.0"` in
its tarball. A lagging manifest therefore publishes a dependent pinned to a
`linklint` that was never published, and npm versions are immutable, so the only
remedy is another release. `tools/check-release-version.mjs` runs first in the
job and refuses the tag rather than letting that reach the registry; it exits
`0` agreement, `1` disagreement, `2` could-not-run, on the same three-way rule
as the other tools here.

`linklint` publishes before the three packages that depend on it, so no window
exists in which an install resolves a dependent whose dependency is not there
yet.

### Why CI publishes and you cannot

Authentication is npm **trusted publishing** (OIDC), not a token. GitLab mints a
short-lived identity token, the npm CLI exchanges it for a publish token that
lives for minutes, and npm attaches a provenance attestation at no extra cost.
Nothing long-lived exists to leak or rotate — which matters here, because this
project is public with `public_jobs` on and job logs are world-readable.

It also happens to be the only thing that works unattended. The npm account's
second factor is a WebAuthn passkey, so a manual `npm publish` raises `EOTP` and
demands a browser handoff, and a passkey is challenge–response — there is no
six-digit code to hand to `--otp=`.

**One-time setup, per package**, at npmjs.com → the package → Settings → Trusted
Publisher:

| Field | Value |
|---|---|
| Publisher | GitLab CI/CD |
| Namespace | `bart-turczynski` |
| Project name | `linklint` |
| Top-level CI file path | `.gitlab-ci.yml` |
| Allowed actions | tick **Allow `npm publish`** |

Three things about that record are easy to get wrong:

- **The CI file path is load-bearing.** Moving or renaming `.gitlab-ci.yml`
  breaks publishing until the record is updated.
- **It cannot be edited.** npm fixes the provider and its fields once the
  connection is created; changing one means deleting it and making a new one.
- **Shared runners only.** npm does not accept OIDC from a self-hosted runner,
  so attaching one to solve a future minutes problem (`LINK-ozgkfjow`) would
  cost this job its authentication.

**A package must already exist before its trusted publisher can be configured** —
npm's settings page needs something to attach the record to. `linklint` exists,
so it can go straight to OIDC. `@linklint/cli`, `@linklint/mcp` and
`@linklint/online` do not, so each needs one bootstrap publish by another means
before its record can be created. Plan the first release around that; it is a
one-time cost per package, not a standing one.

### Why `npm publish` and not `pnpm publish`

pnpm is the workspace tool here but not the publisher. OIDC support is an open
request against pnpm (`pnpm/pnpm#9812`), and pnpm 11 — the major pinned in
`packageManager` — is reported to fail OIDC publishes that worked on pnpm 10
(`pnpm/pnpm#11513`). The npm CLI owns the token exchange, so npm publishes.

That leaves exactly one thing only pnpm can do: rewrite `workspace:*`. npm would
publish the literal string and break every install. So the job has pnpm **pack**
all four packages and npm **publish** the resulting tarballs — each tool does the
half it is good at, and what npm uploads is what pnpm resolved.

### What is not proven yet

The `publish` job has **never run** — no tag has ever been pushed. It is no
longer blocked, though: runner minutes came back with the visibility flip, and
`verify` now executes on both majors.

What blocks a release today is that **`verify` is red on the runner**
(`LINK-ujbttpph`): three tests that pass on macOS fail on the Linux CI image.
`publish` sits behind `verify` by stage ordering, so a tag pushed now would be
correctly refused rather than publishing a tree the matrix rejected. Fix that
first.

When the first tag does go out, its execution is also this job's first test:
read the job log, and check the registry rather than the pipeline's colour.
