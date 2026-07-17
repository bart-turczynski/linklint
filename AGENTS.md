# Agent Instructions

Use committed docs for durable project knowledge. Keep raw planning notes, temporary context, and generated scratch work in `_scratch/`.

Do not commit `_scratch/`, `.fp/`, secrets, dependencies, build outputs, or local caches.

## Git hygiene

`pre-commit` is a Python tool — on non-Python stacks install it with `uv tool install pre-commit` or `pipx install pre-commit`. Enable hooks once per clone:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

The pre-push hook runs `pnpm check` (the same chain as CI). This is the stand-in for branch protection, which is unavailable on this GitHub plan — a push whose tree turns CI red is blocked locally.

## Online roadmap handoff

When assigned `LINK-ddsnssrd` or one of its K/L/M/N descendants, read
[`docs/online-roadmap.md`](docs/online-roadmap.md) before selecting work, then
confirm live status and dependencies with `fp context`, `fp issue show`, and
`fp tree`. FP is the status/dependency source of truth; the committed roadmap is
the durable architecture and resume-order guide.

@FP_AGENTS.md
