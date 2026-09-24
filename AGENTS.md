# linklint

Offline-first URL inspector: a deterministic, explainable verdict on whether a
URL is deceptive.

Keep scratch work in `_scratch/`.

`pnpm check` is the gate; the pre-push hook runs it on every Node major via
`tools/verify.sh`. A leg reported NOT RUN is ungated — a pass on one major is
not a pass on the matrix.

`main` is on GitLab (`bart-turczynski/linklint`, public); there is no branch
protection. Finish a slice, merge to `main`, delete the branch —
`git branch --no-merged main` stays empty — then run `./tools/backup.sh`.

For the verify gate and the `tldts`/`tr46` pin procedure, see CONTRIBUTING.md.
For fp tracker rules and the architecture.md decision trailers, see docs/tracker-hygiene.md.
For hooks, branch discipline and backups, see docs/local-workflow.md.
For unconditional claims in prose, see docs/guarantees.md.
For roadmap work and what is parked, see docs/online-roadmap.md.

@FP_AGENTS.md
