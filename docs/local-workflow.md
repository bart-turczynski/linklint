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

It is also the stand-in for branch protection, which this project has never had.

If the script reports a matrix leg as NOT RUN, that leg is genuinely ungated on
your machine until you install the runtime it names — `brew install node@24` for
the usual case, since Homebrew keeps it keg-only and off `PATH`. Do not read a
pass on one major as a pass on the matrix.

Install the tracker guards in the same pass; see
[*Tracker hygiene*](tracker-hygiene.md).

### Secret scanning

The pre-commit stage runs [gitleaks](https://github.com/gitleaks/gitleaks)
(the upstream hook, at a pinned `rev`) over your **staged changes**. It is the
project's **only** secret scanner. It runs at commit time and not as a GitLab
pipeline job because most pushes here create no pipeline, and GitLab push
protection needs a tier this project does not have (`LINK-tmqonltz`).

It catches credential-shaped strings using gitleaks' full default rule set:
cloud provider keys (AWS, GCP, Azure), forge and package-registry tokens, API
keys for common services, private key blocks, and generic high-entropy
`key=`/`token=`/`secret=` assignments. When it finds one, the commit is
refused. The output is redacted, so the finding does not end up in your
scrollback.

**If it flags a real secret,** unstage it, move it into `.env` (gitignored; see
`.env.example`), and rotate it if it has ever left your machine.

**If it flags a false positive**, which the hostile test corpora make likely,
add a narrow entry to `.gitleaks.toml`:

- scope it with `targetRules` to the one rule that fired, and with `paths` to the
  exact file(s). Add a `regexes` match on the literal value with
  `condition = "AND"` whenever the file could hold other strings;
- add a comment saying why the value is safe.

Do not add a path-only or repo-wide allowlist, do not disable a rule, and do not
use `--no-verify` or `SKIP=gitleaks` to get past it. To check the whole tree,
run `gitleaks dir .`. The hook itself scans only what is staged, so
`pre-commit run gitleaks --all-files` checks the index and not the tree.

## Local hygiene

`main` is on GitLab and in sync, but nothing on that remote gates or reviews it
— there is no branch protection and no required pipeline — so the discipline
below is still the only discipline.

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
