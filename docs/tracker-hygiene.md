# Tracker hygiene

Rules for this repo's fp issue tracker, and for the decision records that
tracker state is supposed to match. The guards that enforce the first section
live in [`tools/fp-extensions/`](../tools/fp-extensions/README.md).

Install this repo's fp extensions once per clone, alongside the pre-commit hooks
(see [*Local workflow*](local-workflow.md)):

```bash
./tools/fp-extensions/install.sh
```

`.fp/` is gitignored, so the extensions are authored in tracked
`tools/fp-extensions/` and symlinked into place. `fp guide` prints the loaded
list.

## Closing comments

**An issue cannot go `done` without a closing comment** (`LINK-crxctgsh`). The
comment must name a commit SHA, a merge request (`merged as !89`, `MR !89`,
`merge request 89`) or PR (`merged as PR #139`), or an explicit exemption with a
reason (`NO-COMMIT: declined on cost, see the analysis above`).
Use the exemption for declined proposals and epics closing on their children's
acceptance — it keeps a commitless close visible and auditable rather than
silent. The rule comes from the `LINK-nlfybbsf` audit, where closing-comment
presence separated verified-clean from defective across 45 issues with no
exceptions.

**Post the closing comment as its own call, before the status change**
(`LINK-ravclvca`). `fp issue update --status done --comment "..."` applies the
comment *after* the update, so when the guard refuses the close the comment is
not posted at all — and the retry is refused for the same reason:

```bash
fp comment <id> "merged as !89"
fp issue update --status done <id>
```

**A named commit must also be a *merged* commit** (`LINK-nwqrqjdc`). When the
closing comment names a SHA, the guard now checks it is an ancestor of local
`main` and refuses the close otherwise. Merge first, then close:

```bash
git checkout main && git merge --ff-only <branch>
```

An MR or PR reference or a `NO-COMMIT:` exemption still discharges on its own —
the evidence for those lives where the guard cannot reach. A SHA-shaped token
that resolves to no commit (a hex id inside a worktree path reads the same) is
reported as possibly not a commit reference, not as a missing commit. The check
fails **open** if git is unavailable or `main` is missing, since an unusable
tracker is worse than an unverified close.

This closes the hole that cost `LINK-wgsbhovi` and `LINK-nwqrqjdc`: **nine
branches and twelve issues** were closed citing a SHA that sat on a branch
nobody merged, and the old guard passed every one because it only checked that a
SHA was *named*. Sweep for survivors with `git branch --no-merged main`.

## Titles carry the outcome

**`done` means shipped. Work that ends any other way says so in its title**
(`LINK-owjeewpe`):

| Prefix | Meaning | End state |
|---|---|---|
| `[SCRATCHED]` | Abandoned — the code never merged and nothing replaces it | `done` |
| `[SUPERSEDED]` | Replaced by another issue; name it, e.g. `(by LINK-tqlqshlt)` | `done` |
| `[PARKED]` | Not started and not scheduled | stays `todo` |
| `[DECLINED]` | Considered and rejected under a recorded decision — not merely dropped, and not to be revisited under the current architecture | `done` |
| `[ALREADY-SATISFIED]` | The ask was found to hold on `main` before any work started, so there was nothing to build | `done` |

The prefix goes in the **title**, not only in a label or a comment: `fp tree`
and `fp issue list` render neither, and the audit's finding was that abandonment
was discoverable *only* by reading a comment. Set the matching `labels` value
too, for filtering.

A `[SCRATCHED]`/`[SUPERSEDED]` title is its own closing-comment exemption, so
the guard above accepts it — there is no evidence to cite. `[DECLINED]` and
`[ALREADY-SATISFIED]` are **not** exemptions: both rest on evidence, so both
still need a closing comment carrying it — the governing decision (record or
issue id) for `[DECLINED]`, the probe that showed the behavior present on `main`
for `[ALREADY-SATISFIED]`.

`[ALREADY-SATISFIED]` replaces the undocumented comment-only `VERIFY-AND-CLOSE …
Already implemented on main:` convention (`LINK-yotoonba`, `LINK-zkybktdk`,
`LINK-xpdvmjdw`), which put the outcome where no listing renders it — the exact
failure this rule exists to prevent. Keep the probe in the comment; move the
outcome into the title.

## Decision records

**A decision record that adopts a mechanism must name the ticket implementing
it** (`LINK-hsoazwuu`). Any `**… — ADOPTED.**` block in
[`architecture.md`](architecture.md) has to end with a trailer:

```markdown
**Pending (`LINK-abcdefgh`).**       <- adopted, not yet built; keep the record in future tense
**Implemented (`LINK-abcdefgh`).**   <- landed; present tense is now earned
```

`packages/core/test/docs-validation.test.ts` asserts this, so a record without a
trailer fails `pnpm check`.

This is the root cause of the `LINK-tbqeqqvv` failure. §6.1.1 shipped in PR #122
describing an adopted mechanism in the **present tense** while its
implementation ticket sat unimplemented for weeks — so every downstream reader
saw a working feature and nothing in the repo could contradict them. Present
tense is a claim about what the code does; do not write it until the code does
it.

The same doctrine governs unconditional prose claims; see
[*Guarantee register*](guarantees.md).
