# linklint

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
  an MCP server surface (`check_url` / `check_domain`).
- **Embeddable** — a clean, synchronous library first; every other surface consumes it.

## Status

v1 implements lexical (Layer 1) detection only: homograph/confusable analysis,
script-mixing, invisible/bidi characters, userinfo deception, IP obfuscation,
embedded-domain subdomains, risky TLDs, percent-encoding obfuscation, and dangerous
schemes. Resolution (redirects) and reputation (feeds) are roadmap.

## API

```ts
import { inspect } from 'linklint';

const result = inspect('https://paypal.com@evil.com/login');
// → { status: 'ok', score: 0.5, severity: 'medium', reasons: [...], ... }
//   paypal.com is a username — the real host is evil.com
```

`inspect(input, options?)` is **synchronous**, does **no** network or filesystem I/O,
and **never throws** — unparseable input returns `status: "invalid"` (which is *not*
benign). See [`docs/reason-codes.md`](../../docs/reason-codes.md) and
[`docs/scoring.md`](../../docs/scoring.md) for the full contract.

The stable root API is `inspect()`, the result/schema types, and versioned
metadata helpers. The root also keeps a legacy advanced compatibility window for
detector, policy, parser, unicode, and reference-data helpers that existed before
secondary entry points. New advanced consumers should import from
`linklint/experimental`, `linklint/metadata`, or `linklint/data`; those subpaths
are the documented migration path if the root is narrowed in a future major.

## License

MIT.
