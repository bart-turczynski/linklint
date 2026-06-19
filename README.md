# linklint

> An explainable, offline-first, agent-native **URL inspector** — "safe-chain for links."

Hand **linklint** a single URL — from an email, a chat message, or an LLM agent's tool
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

## Usage

```ts
import { inspect } from 'linklint';

const r = inspect('https://paypal.com@xn--pypal-4ve.ru/login');
r.severity; // 'high'
r.score;    // 0.7
r.reasons;  // [{ code: 'userinfo_present', ... }, { code: 'mixed_script', ... }, ...]
```

`inspect()` is synchronous, does no network/filesystem I/O, and never throws —
unparseable input returns `status: "invalid"` (which is *not* benign). It also runs
as a local MCP server so an agent can check a URL before fetching it
(`packages/mcp`, tools `check_url` / `check_domain`).

## Repository layout

This is a pnpm monorepo.

| Path | What |
|------|------|
| `packages/core` | The `linklint` npm package — the source of truth (`inspect()`, 12 lexical detectors, scoring, schema). |
| `packages/mcp` | `@linklint/mcp` — a thin, local-only MCP server (`check_url` / `check_domain`). |
| `docs/architecture.md` | System architecture (channels, pipeline, result contract, layers). |
| `docs/reason-codes.md`, `docs/scoring.md` | Reason-code registry and version-pinned scoring. |
| `docs/PRD.md` | Product requirements. |
| `docs/IDEAS.md`, `docs/IDEAS-ADDENDUM.md` | Source material. |
| `features/` | Cucumber success-criteria / critical-path specs. |

## Development

```sh
pnpm install
pnpm check        # build + typecheck + Vitest + Cucumber (the verify gate CI runs)
```

This project uses [pre-commit](https://pre-commit.com); enable hooks once per clone:

```sh
pre-commit install && pre-commit install --hook-type pre-push
```

## Status

v1 is implemented: lexical (Layer 1) detection only — offline, deterministic,
< 5 ms per call. Twelve detectors, probabilistic-OR scoring, a stable versioned
schema, and a local MCP server. Resolution (redirects/shorteners) and reputation
(feeds) are roadmap. See `docs/architecture.md`.

## License

MIT — see [LICENSE](./LICENSE).
