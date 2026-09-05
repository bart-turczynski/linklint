# Naming history — settled, do not re-litigate

Promoted 2026-08-26 from Claude's auto-memory store, which is being retired.

The project started as **`safe-url`**, was renamed **`urlic`**, and is now **`linklint`**.

`urlic` and every short `url*` / `*url` mash — `urlint`, `urllint`, `url-lint` — are blocked by
**npm's new-package similarity filter**, which reads them as too close to `url`, `urllib`,
`urix` and `ulid`. So do **not** suggest reverting to any of them, however much better they
read.

`linklint` was chosen because it is distinctive enough to clear that filter while keeping the
"lint your links" concept intact.

For orientation, the identity this name attaches to: an explainable, offline-first, agent-native
URL inspector — "safe-chain for links" — that detects deceptive URLs (homographs, confusables,
userinfo spoofs, IP obfuscation) lexically and offline, with named reason codes. v1 is Layer-1
lexical only; resolution and reputation are roadmap. Repo `~/Projects/linklint`, GitLab
`bart-turczynski/linklint` (public), npm `linklint` (published `0.0.1`, a throwing
placeholder). pnpm TS monorepo; `packages/core` is the publishable `linklint` package; MIT.

The forge and the visibility above are both corrections, made 2026-09-05 under
`LINK-wxofepqm`. This paragraph was promoted with "GitHub … (private)" in it: GitLab is the
only forge this project uses, and the project was made public on 2026-09-05 — the flip that
restored shared-runner minutes (`LINK-ozgkfjow`).

See also `PRD.md`, `architecture.md`, `IDEAS.md`.
