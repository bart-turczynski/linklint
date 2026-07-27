# Agent Instructions

Use committed docs for durable project knowledge. Keep raw planning notes, temporary context, and generated scratch work in `_scratch/`.

Do not commit `_scratch/`, `.fp/`, secrets, dependencies, build outputs, or local caches.

## Git hygiene

`pre-commit` is a Python tool — on non-Python stacks install it with `uv tool install pre-commit` or `pipx install pre-commit`. Enable hooks once per clone:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

The pre-push hook runs `pnpm check` (the same chain as CI). This is the stand-in for branch protection, which is unavailable on this GitHub plan — a push whose tree turns CI red is blocked locally.

## Tracker hygiene

Install this repo's fp extensions once per clone, alongside the pre-commit hooks:

```bash
./tools/fp-extensions/install.sh
```

`.fp/` is gitignored, so the extensions are authored in tracked `tools/fp-extensions/` and symlinked into place. `fp guide` prints the loaded list.

**An issue cannot go `done` without a closing comment** (`LINK-crxctgsh`). The comment must name a commit SHA, a PR (`merged as PR #139`), or an explicit exemption with a reason (`NO-COMMIT: declined on cost, see the analysis above`). Use the exemption for declined proposals and epics closing on their children's acceptance — it keeps a commitless close visible and auditable rather than silent. The rule comes from the `LINK-nlfybbsf` audit, where closing-comment presence separated verified-clean from defective across 45 issues with no exceptions.

**`done` means shipped. Work that ends any other way says so in its title** (`LINK-owjeewpe`):

| Prefix | Meaning |
|---|---|
| `[SCRATCHED]` | Abandoned — the code never merged and nothing replaces it |
| `[SUPERSEDED]` | Replaced by another issue; name it, e.g. `(by LINK-tqlqshlt)` |
| `[PARKED]` | Not started and not scheduled; stays `todo` |

The prefix goes in the **title**, not only in a label or a comment: `fp tree` and `fp issue list` render neither, and the audit's finding was that abandonment was discoverable *only* by reading a comment. Set the matching `labels` value too, for filtering. A `[SCRATCHED]`/`[SUPERSEDED]` title is its own closing-comment exemption, so the guard above accepts it.

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
