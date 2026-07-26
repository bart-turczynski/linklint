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

Built-in inspection implements lexical (Layer 1) detection only:
homograph/confusable analysis, script-mixing, invisible/bidi characters,
userinfo deception, IP obfuscation, embedded-domain subdomains, risky TLDs,
percent-encoding obfuscation, and dangerous schemes. The package also ships the
pure `inspectAsync()` orchestration/contracts for caller-supplied resolution and
reputation work; concrete network transports and provider adapters remain
roadmap and do not enter this package.

## API

```ts
import { inspect } from 'linklint';

const result = inspect('https://paypal.com@evil.com/login');
// → { status: 'ok', score: 0.5, severity: 'medium', reasons: [...], ... }
//   paypal.com is a username — the real host is evil.com
```

`inspect(input, options?)` is **synchronous**, does **no** network or filesystem I/O,
and **never throws** — unparseable input returns `status: "invalid"` (which is *not*
benign). This holds unconditionally: a non-string argument returns `invalid` too,
rather than a `TypeError`. See [`docs/reason-codes.md`](../../docs/reason-codes.md) and
[`docs/scoring.md`](../../docs/scoring.md) for the full contract.

The stable root API includes `inspect()`, opt-in `inspectAsync()`, the structured
enrichment/cache/governor contracts, result/schema types, and versioned metadata
helpers. The root also keeps a legacy advanced compatibility window for detector,
policy, parser, unicode, and reference-data helpers that existed before secondary
entry points. New advanced consumers should import from
`linklint/experimental`, `linklint/metadata`, or `linklint/data`; those subpaths
are the documented migration path if the root is narrowed in a future major.

`inspectAsync()` is the opt-in orchestration surface for caller-supplied online
work. New enrichers return versioned, source-attributed outcomes and evidence;
optional `<layer>:<id>` dependencies create deterministic stages, and downstream
enrichers receive prior structured outcomes through their context. Independent
work remains parallel, while failed prerequisites become explicit skipped
outcomes. Host-scoped suppressions are evaluated against each outcome's actual
subject, so allowing the original host cannot hide a discovered destination.
Every configured source has a 5-second runner deadline by default, even without
a governor; positive finite `timeoutMs` values override it and `null` explicitly
opts out. Provider, cache, cache-key, and governor exceptions become attributed
degradation outcomes and cannot reject or indefinitely stall sibling work.
The opt-in `EnrichmentCache` accepts synchronous or Promise-capable stores,
stores only validated structured reports, and validates cache hits before use.
Static `cacheTtlMs` remains supported; `cacheTtlMsFor(report, context)` can derive
per-response positive/no-hit lifetimes from source freshness. Skipped, failed,
and partial reports are not cached, and cache key material remains the adapter's
privacy-safe projection rather than the full URL.
The synchronous package itself still performs no network I/O. See
[`docs/enrichment-outcomes.md`](../../docs/enrichment-outcomes.md) for the public
contract, status semantics, validation rules, and legacy-findings migration.

## License

MIT.
