# Agent Instructions

Use committed docs for durable project knowledge. Keep raw planning notes, temporary context, and generated scratch work in `_scratch/`.

Do not commit `_scratch/`, `.fp/`, secrets, dependencies, build outputs, or local caches.

## Git hygiene

`pre-commit` is a Python tool — on non-Python stacks install it with `uv tool install pre-commit` or `pipx install pre-commit`. Enable hooks once per clone:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

The pre-push hook runs `pnpm check` (the same chain as CI). This is the stand-in for branch protection, which is unavailable on this GitHub plan — a push whose tree turns CI red is blocked locally.

### While the remote is unreachable

`main` lives on one machine, so local hygiene is the only hygiene.

**Nothing may sit on a branch.** Finish the slice, merge to `main`, delete the branch. `git branch --no-merged main` should be empty every time you check — nine branches accumulated there unnoticed and cost `LINK-wgsbhovi` and `LINK-nwqrqjdc` twelve wrongly-closed issues.

**Back up after every landed unit** with `./tools/backup.sh`. It writes a verified bundle *and* a `.fp/` archive, because `.fp/` is gitignored and no `git bundle` has ever contained it — losing it would lose every decision record while leaving the code intact.

**Backups stay on this volume — decided, not overlooked.** `~/Projects/linklint-backups` shares a filesystem with the working copy, so it protects against a bad git operation, a bad merge, or a deleted `.fp/`, and not against losing the disk. That residual is accepted. Do not propose an off-volume, cloud, or remote destination.

**Reflog expiry is disabled** in this clone (`gc.reflogExpire=never`, `gc.reflogExpireUnreachable=never`, `gc.pruneExpire=90.days.ago`), so `git gc` cannot quietly discard the history that makes a stranded commit recoverable. Re-apply after a fresh clone.

## Tracker hygiene

Install this repo's fp extensions once per clone, alongside the pre-commit hooks:

```bash
./tools/fp-extensions/install.sh
```

`.fp/` is gitignored, so the extensions are authored in tracked `tools/fp-extensions/` and symlinked into place. `fp guide` prints the loaded list.

**An issue cannot go `done` without a closing comment** (`LINK-crxctgsh`). The comment must name a commit SHA, a PR (`merged as PR #139`), or an explicit exemption with a reason (`NO-COMMIT: declined on cost, see the analysis above`). Use the exemption for declined proposals and epics closing on their children's acceptance — it keeps a commitless close visible and auditable rather than silent. The rule comes from the `LINK-nlfybbsf` audit, where closing-comment presence separated verified-clean from defective across 45 issues with no exceptions.

**A named commit must also be a *merged* commit** (`LINK-nwqrqjdc`). When the closing comment names a SHA, the guard now checks it is an ancestor of local `main` and refuses the close otherwise. Merge first, then close:

```bash
git checkout main && git merge --ff-only <branch>
```

A PR reference or a `NO-COMMIT:` exemption still discharges on its own — the evidence for those lives where the guard cannot reach. The check fails **open** if git is unavailable or `main` is missing, since an unusable tracker is worse than an unverified close.

This closes the hole that cost `LINK-wgsbhovi` and `LINK-nwqrqjdc`: **nine branches and twelve issues** were closed citing a SHA that sat on a branch nobody merged, and the old guard passed every one because it only checked that a SHA was *named*. Sweep for survivors with `git branch --no-merged main`.

**`done` means shipped. Work that ends any other way says so in its title** (`LINK-owjeewpe`):

| Prefix | Meaning | End state |
|---|---|---|
| `[SCRATCHED]` | Abandoned — the code never merged and nothing replaces it | `done` |
| `[SUPERSEDED]` | Replaced by another issue; name it, e.g. `(by LINK-tqlqshlt)` | `done` |
| `[PARKED]` | Not started and not scheduled | stays `todo` |
| `[DECLINED]` | Considered and rejected under a recorded decision — not merely dropped, and not to be revisited under the current architecture | `done` |
| `[ALREADY-SATISFIED]` | The ask was found to hold on `main` before any work started, so there was nothing to build | `done` |

The prefix goes in the **title**, not only in a label or a comment: `fp tree` and `fp issue list` render neither, and the audit's finding was that abandonment was discoverable *only* by reading a comment. Set the matching `labels` value too, for filtering.

A `[SCRATCHED]`/`[SUPERSEDED]` title is its own closing-comment exemption, so the guard above accepts it — there is no evidence to cite. `[DECLINED]` and `[ALREADY-SATISFIED]` are **not** exemptions: both rest on evidence, so both still need a closing comment carrying it — the governing decision (record or issue id) for `[DECLINED]`, the probe that showed the behavior present on `main` for `[ALREADY-SATISFIED]`.

`[ALREADY-SATISFIED]` replaces the undocumented comment-only `VERIFY-AND-CLOSE … Already implemented on main:` convention (`LINK-yotoonba`, `LINK-zkybktdk`, `LINK-xpdvmjdw`), which put the outcome where no listing renders it — the exact failure this rule exists to prevent. Keep the probe in the comment; move the outcome into the title.

## Decision records

**A decision record that adopts a mechanism must name the ticket implementing it** (`LINK-hsoazwuu`). Any `**… — ADOPTED.**` block in `docs/architecture.md` has to end with a trailer:

```markdown
**Pending (`LINK-abcdefgh`).**       <- adopted, not yet built; keep the record in future tense
**Implemented (`LINK-abcdefgh`).**   <- landed; present tense is now earned
```

`packages/core/test/docs-validation.test.ts` asserts this, so a record without a trailer fails `pnpm check`.

This is the root cause of the `LINK-tbqeqqvv` failure. §6.1.1 shipped in PR #122 describing an adopted mechanism in the **present tense** while its implementation ticket sat unimplemented for weeks — so every downstream reader saw a working feature and nothing in the repo could contradict them. Present tense is a claim about what the code does; do not write it until the code does it.

## Guarantee statements

**Never / always / unconditional / guarantee is either pinned by a test or qualified in the prose** (`LINK-ltyjctpf`). [`docs/guarantees.md`](docs/guarantees.md) is the register: every such claim across `docs/` and the package READMEs, classified, with the test that pins it.

`packages/core/test/guarantee-register.test.ts` holds a per-file budget of guarantee-word lines, so writing a new unconditional claim fails `pnpm check` until you pin it, qualify it, or classify it as rhetorical in §H. The budget exists to move the triage to authoring time — while you still know whether the code does what the sentence says.

The root cause is `LINK-zsbeqtcr`: an unqualified "`inspect()` never throws" that was false for non-string input and shipped for weeks, because nothing in the repository could contradict it. Same failure shape as the decision-record rule above.

## Online roadmap handoff

When assigned `LINK-ddsnssrd` or one of its K/L/M descendants, read
[`docs/online-roadmap.md`](docs/online-roadmap.md) before selecting work, then
confirm live status and dependencies with `fp context`, `fp issue show`, and
`fp tree`. FP is the status/dependency source of truth; the committed roadmap is
the durable architecture and resume-order guide.

`LINK-ddsnssrd` is **done**: Epics K, L, and M are complete through their
acceptance gates. Epic N (monitoring service) and Epic P (licensed third-party
providers) were its two remaining branches; both are now **parked** under
`LINK-illixeqw` and are no longer coordinator scope. Do not propose or start
either without an explicit instruction — when asked what is available, report
only that this work is parked until further notice.

@FP_AGENTS.md
