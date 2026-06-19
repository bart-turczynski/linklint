# urlic

> An explainable, offline-first, agent-native **URL inspector** — "safe-chain for links."

Hand **urlic** a single URL — from an email, a chat message, or an LLM agent's tool
call — and it tells you whether the URL is *deceptive*, and **explains exactly why**,
with no network and no data leaving the machine.

It generalizes one insight from hostname analysis: **if `normalize(input) !== input`,
something may be hiding in the URL.**

## Principles

- **Explainable, not binary** — every verdict carries named, documented reason codes
  (`mixed_script`, `userinfo_present`, `ip_obfuscation`, …), never a bare boolean.
- **Offline-first** — the v1 core runs with zero network. Deterministic and instant.
- **Agent-native** — built for "check a link *before* you fetch it," exposed over MCP.
- **Embeddable** — a clean, synchronous library first; every other surface consumes it.

## Repository layout

This is a pnpm monorepo.

| Path | What |
|------|------|
| `packages/core` | The `urlic` npm package — the source of truth (`inspect()`). *Placeholder release; implementation in progress.* |
| `docs/architecture.md` | System architecture (channels, pipeline, result contract, layers). |
| `PRD.md` | Product requirements. |
| `IDEAS.md`, `IDEAS-ADDENDUM.md` | Source material. |
| `src/`, `features/` | Workspace-root scaffold smoke test (typecheck + cucumber). |

## Development

```sh
pnpm install
pnpm check        # typecheck + feature tests (the verify gate CI runs)
```

This project uses [pre-commit](https://pre-commit.com); enable hooks once per clone:

```sh
pre-commit install && pre-commit install --hook-type pre-push
```

## Status

v1 targets lexical (Layer 1) detection only — offline, deterministic. Resolution
(redirects/shorteners) and reputation (feeds) are roadmap. See `docs/architecture.md`.

## License

MIT — see [LICENSE](./LICENSE).
