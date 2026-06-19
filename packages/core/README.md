# linklint

> ⚠️ **Placeholder release (`0.0.2`).** The implementation is in progress —
> `inspect()` currently throws. Watch this space.

**linklint** is an explainable, offline-first **URL inspector**. Hand it a single URL —
from an email, a chat message, or an LLM agent's tool call — and it tells you whether
the URL is *deceptive*, and **explains exactly why**, with no network and no data
leaving the machine.

It generalizes one insight from hostname analysis: **if `normalize(input) !== input`,
something may be hiding in the URL.**

## Why

- **Explainable, not binary** — every verdict carries named, documented reason codes
  (`mixed_script`, `userinfo_present`, `ip_obfuscation`, …), not a bare boolean.
- **Offline-first** — the core runs with zero network. Deterministic and instant.
- **Agent-native** — built for the "check a link *before* you fetch it" use case, with
  an MCP server surface planned.
- **Embeddable** — a clean, synchronous library first; every other surface consumes it.

## Status

v1 implements lexical (Layer 1) detection only: homograph/confusable analysis,
script-mixing, invisible/bidi characters, userinfo deception, IP obfuscation,
embedded-domain subdomains, risky TLDs, percent-encoding obfuscation, and dangerous
schemes. Resolution (redirects) and reputation (feeds) are roadmap.

## Planned API

```ts
import { inspect } from 'linklint';

const result = inspect('https://paypal.com@xn--pypal-4ve.ru/login');
// → { status: 'ok', score: 0.7, severity: 'high', reasons: [...], ... }
```

## License

MIT (provisional — license selection is still open; see PRD OQ-4).
