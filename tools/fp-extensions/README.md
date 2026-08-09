# fp extensions

Issue-tracker guards for this repo, loaded by [fp](https://fiberplane.com) from
`.fp/extensions/`.

`.fp/` is gitignored — it holds local tracker state — so an extension authored in
place would vanish on the next fresh clone. These guards exist precisely because
tracker state went wrong once, so the source of truth is this tracked directory
and `install.sh` symlinks each subdirectory into `.fp/extensions/`. Editing a
file here takes effect immediately; there is no copy step to forget.

```bash
./tools/fp-extensions/install.sh   # once per clone
fp guide                           # prints the loaded extension list
```

## `closing-comment-required` — no `done` without a closing comment

Blocks the `issue:status:changing` transition to `done` unless some comment on
the issue names one of:

| Form | Example |
|---|---|
| PR or issue reference | `merged as PR #139` |
| Commit SHA | `landed in 71debd9` |
| Explicit exemption + reason | `NO-COMMIT: declined on cost, see the analysis above` |

A `[SCRATCHED]` or `[SUPERSEDED]` title prefix also passes, with no comment
needed — such a title already declares the commitless close in every listing
(see `LINK-owjeewpe` and [`docs/tracker-hygiene.md`](../../docs/tracker-hygiene.md)).

**Why.** The `LINK-nlfybbsf` audit (2026-07-26) checked 45 issues and swept 239.
Closing-comment presence separated good from bad perfectly: `LINK-tbqeqqvv`,
`LINK-hastsuzd` and `LINK-njcklhlg` each closed with zero comments and zero
referencing commits — three for three defective — while every issue carrying a
"merged as PR #N" comment verified clean. `tbqeqqvv` is the expensive one: it
closed unimplemented while `architecture.md` §6.1.1 already described its
mechanism in the present tense, so nothing in the repo could contradict the
claim for weeks.

**Why comments and not the git log.** The same audit found the "no referencing
commit" signature fires 59/239 standalone and is **~90% false positive**, because
the commit-message convention only starts at PR #7. A git-log guard would be
noise; this one reads comments only.

**Why the exemption exists.** Plenty of issues close correctly with no commit —
declined proposals (the Tranco family, `LINK-gxwyxkyg`), superseded work, and
epics closing on their children's acceptance gates. Without a hatch the guard
would be wrong for a whole legitimate class and would get disabled the first time
it got in the way. `NO-COMMIT:` requires a stated reason, so a commitless close
stays visible and auditable instead of silent.

The predicate is unit-tested in `tests/unit/fp-closing-comment-guard.test.ts` and
runs in `pnpm check`. It is split into `predicate.ts` — deliberately free of any
`@fiberplane/extensions` import — so the test never drags fp's home-directory type
paths into the repo's typecheck.
