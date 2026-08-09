# Local workflow

Hooks, branch discipline, and backups. The gate those hooks run is documented in
[*The verify gate*](../CONTRIBUTING.md#the-verify-gate); this page covers the
local hygiene around it.

## Hooks

`pre-commit` is a Python tool — on non-Python stacks install it with
`uv tool install pre-commit` or `pipx install pre-commit`. Enable hooks once per
clone:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

The pre-push hook runs `tools/verify.sh`: a `--frozen-lockfile` install, then
`pnpm check` on every Node major in the matrix (24 and 26). This is the
**primary** gate, not a mirror of a remote one — GitLab's shared runners are
metered, so `.gitlab-ci.yml` creates no pipeline for an ordinary push and only
builds on dependency, toolchain, pinned-data and tag changes.

It is also the stand-in for branch protection, which this project has never had
on either host.

If the script reports a matrix leg as NOT RUN, that leg is genuinely ungated on
your machine until you install the runtime it names — `brew install node@24` for
the usual case, since Homebrew keeps it keg-only and off `PATH`. Do not read a
pass on one major as a pass on the matrix.

Install the tracker guards in the same pass; see
[*Tracker hygiene*](tracker-hygiene.md).

## While the remote is unreachable

`main` lives on one machine, so local hygiene is the only hygiene.

**Nothing may sit on a branch.** Finish the slice, merge to `main`, delete the
branch. `git branch --no-merged main` should be empty every time you check —
nine branches accumulated there unnoticed and cost `LINK-wgsbhovi` and
`LINK-nwqrqjdc` twelve wrongly-closed issues.

**Back up after every landed unit** with `./tools/backup.sh`. It writes a
verified bundle *and* a `.fp/` archive, because `.fp/` is gitignored and no
`git bundle` has ever contained it — losing it would lose every decision record
while leaving the code intact.

**Backups stay on this volume — decided, not overlooked.**
`~/Projects/linklint-backups` shares a filesystem with the working copy, so it
protects against a bad git operation, a bad merge, or a deleted `.fp/`, and not
against losing the disk. That residual is accepted. Do not propose an
off-volume, cloud, or remote destination.

**Reflog expiry is disabled** in this clone (`gc.reflogExpire=never`,
`gc.reflogExpireUnreachable=never`, `gc.pruneExpire=90.days.ago`), so `git gc`
cannot quietly discard the history that makes a stranded commit recoverable.
Re-apply after a fresh clone.
