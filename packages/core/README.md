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
userinfo deception, IP obfuscation, embedded-domain subdomains,
file-extension TLDs, percent-encoding obfuscation, and dangerous schemes. The package also ships the
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

## Comparing two URLs

`compareUrls(left, right)` answers a different question from `inspect()`'s: not
"is this string deceptive" but "do these two URLs address the same origin, or the
same site". It is synchronous, offline, and total — a non-string argument comes
back as `"undetermined"` rather than a `TypeError`.

```ts
import { compareUrls } from 'linklint';

compareUrls('https://ex.com:443/a', 'https://EX.com./b').sameOrigin;
// → 'same'  (default port elided, case folded, root label dropped)

compareUrls('https://alice.github.io/', 'https://mallory.github.io/');
// → sameSite: 'different', sameSiteIcann: 'same'
```

Three answers, each `'same' | 'different' | 'undetermined'`:

| Field | Question |
| --- | --- |
| `sameOrigin` | Same scheme, host and port, after the canonicalization below. |
| `sameSite` | Same registrable domain under the PSL's **PRIVATE-inclusive** view, so two tenants of one multi-tenant platform stay distinct. |
| `sameSiteIcann` | The same under the ICANN-only view — the one `inspect().parsed.registrableDomain` reports. |

Both sides of the comparison come back on `left` and `right` as the canonical
view they were compared on (`scheme`, `host`, `port`, `site`, `siteIcann`,
`originKind`), so an answer can be read rather than taken on trust.

**Why this is a function and not a recipe.** `inspect().parsed` reports what the
URL *wrote*, which is what the character-level detectors need, so it applies none
of the four normalizations a comparison wants: `https://ex.com:443/` keeps port
`443`, `http://EX.com/` keeps host `EX.com`, `https://ex.com./` keeps the root
label, and the A-label and U-label spellings of one host land on different values
— `registrableDomain` included. `compareUrls()` applies all four: UTS-46 ToASCII
over the host (which covers case and the IDN spellings in one step), canonical
rendering for IP literals, default-port elision, and a single trailing root label
removed. See `docs/architecture.md` §6.1.9 for the specification and the
measurement that decided it ships.

**Opaque origins are `'different'`, not `'undetermined'`.** `data:`, `file:` and
`about:blank` are settled by the URL Standard — each parse gets a fresh opaque
origin, so two parses of one identical `data:` string are two origins.
`'undetermined'` is kept for what this function could not work out: an input that
did not parse, a host UTS-46 rejects, or a bare authority with no scheme. Read
`!== 'same'` as weaker than `=== 'different'`.

The result is **advisory**: a relationship, not a permission. It carries
`pslSnapshot`, the provenance of the bundled PSL both site answers rest on, whose
`stale` flag is one-directional — it can show proven staleness and cannot show
freshness, because the pinned date is a packaging proxy. Test `=== true`; read
`null` as unknown.

## License

MIT.
