# linklint

> An explainable, offline-first, agent-native **URL inspector** — _"safe-chain for links."_

[![npm version](https://img.shields.io/npm/v/linklint.svg)](https://www.npmjs.com/package/linklint)
[![Socket Badge](https://socket.dev/api/badge/npm/package/linklint)](https://socket.dev/npm/package/linklint)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/linklint)](https://bundlephobia.com/package/linklint)
[![node](https://img.shields.io/badge/node-%3E%3D24-3c873a.svg)](./packages/core/package.json)
[![types](https://img.shields.io/badge/types-included-3178c6.svg?logo=typescript&logoColor=white)](./packages/core/src/index.ts)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

<sub>**Verification:** every commit passes `pnpm check` — build, typecheck, 3568
tests, 51 feature scenarios — on both supported Node majors before it is pushed.
Remote CI runs the same matrix on dependency, toolchain and pinned-data changes.
There is no CI badge here because the pipeline lives on a private project and
the badge would not render; see
[CONTRIBUTING.md](./CONTRIBUTING.md#the-verify-gate) for how the gate is split.</sub>

Hand **linklint** a single URL — from an email, a chat message, or an LLM agent's
tool call — and it tells you whether the URL is _deceptive_, and **explains exactly
why**, with no network and no data leaving the machine.

It generalizes one insight from hostname analysis: **if `normalize(input) !== input`,
something may be hiding in the URL.** linklint turns that intuition into 37 deterministic
detectors, each emitting a named, documented reason code (four — the agent-mode
prompt-injection, credential-harvesting, data-exfiltration, and cloud-metadata SSRF
detectors — are opt-in via `agentMode`).

```ts
import { inspect } from 'linklint';

inspect('https://paypal.com@evil.com/login');
// → severity: 'medium', score: 0.5, reasons: ['userinfo_present']
//   the real host is evil.com — "paypal.com" is just a username

inspect('https://раypal.com');
// → severity: 'critical', score: 1.0
//   reasons: ['homograph_latin_skeleton', 'mixed_script', 'idn_host', ...]
//   "раypal" is Cyrillic letters disguised as "paypal"
//   (the punycode spelling, xn--ypal-43d9g.com, scores identically)

inspect('javascript:fetch("//evil.example")');
// → severity: 'critical', score: 0.9, reasons: ['dangerous_scheme']
```

## Why linklint

- **Explainable, not binary** — every verdict carries named, documented reason codes
  (`mixed_script`, `userinfo_present`, `ip_obfuscation`, …), each with a human-readable
  `detail` string. No black-box score, no bare boolean.
- **Offline-first** — zero network, zero telemetry, no runtime filesystem I/O.
  Deterministic and typically **< 5 ms** per call. Nothing about the URL ever leaves
  the machine.
- **Agent-native** — built for _"check a link before you fetch it,"_ and exposed over
  [MCP](#mcp-server-check-before-you-fetch) so an LLM agent can vet a URL before opening it.
- **Embeddable** — a clean, synchronous, dependency-light library first; every other
  surface (MCP server, CLI) consumes it.
- **`inspect()` never throws** — unparseable input returns `status: "invalid"`
  (which is _not_ benign), so it is safe to call on fully untrusted input —
  including a non-string, which fails closed rather than throwing.

## Install

```sh
npm install linklint        # or: pnpm add linklint / yarn add linklint
```

Requires Node ≥ 24. Ships with TypeScript types. Two runtime dependencies
(`tldts` for the Public Suffix List, `tr46` for IDNA/UTS-46).

## Quick start

```ts
import { inspect } from 'linklint';

const r = inspect('https://раypal.com');

r.status;    // 'ok'        — input parsed (vs. 'invalid')
r.score;     // 1.0         — [0,1], probabilistic-OR over detector weights
r.severity;  // 'critical'  — 'info' | 'low' | 'medium' | 'high' | 'critical'
r.reasons;   // named, weighted, explained findings — see below
```

Each reason is fully self-describing:

```jsonc
{
  "code": "homograph_skeleton_collision",
  "layer": "lexical",
  "detail": "registrable domain 'раypal.com' has the same UTS#39 confusable skeleton ('paypal.com') as the known brand 'paypal.com' — a single-script whole-label homograph",
  "weight": 0.5
}
```

## What linklint protects against

linklint runs **37 offline detectors** grouped into the families below: 4 structural
scans and 33 parsed-context detectors, including 4 agent-mode detectors
(prompt-injection, credential-harvesting, data-exfiltration, and
cloud-metadata SSRF) that are opt-in via `agentMode` and off by default. Every
example is real output. A clean URL like `https://github.com` returns `score: 0`,
`severity: 'info'`, `reasons: []`.

### 1. Authority spoofing — "which host am I actually talking to?"

The most dangerous class: the URL _looks_ like it goes to a trusted host, but the real
authority is somewhere else.

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://paypal.com@evil.com/login` | `userinfo_present` | `paypal.com` is a **username** — the real host is `evil.com`. |
| `https://paypal.com.login.evil.tk/` | `embedded_domain_in_subdomain` | `paypal.com` is a **subdomain label**; the registrable domain is `evil.tk`. |
| `https://google.com#@evil.com` | `ambiguous_authority` | Fragment-in-authority — parsers disagree on the real host. |
| `http://2130706433/` | `ip_obfuscation`, `ip_loopback` | Decimal-encoded `127.0.0.1` — an IP wearing a disguise that resolves to loopback. |
| `http://169.254.169.254/` | `ip_cloud_metadata` (+ `ssrf_cloud_metadata` under `agentMode`) | Literal cloud instance-metadata endpoint — the canonical SSRF credential-theft target. Lands `high` by default; **blocks (`critical`) under `agentMode`**, where a fetch is in flight. |
| `https://evil。com/` | `separator_lookalike` | `。` (U+3002) normalizes to `.` — a fake label separator. |
| `https://a.b.c.d.paypal.com.evil.tk/` | `excessive_subdomain_depth` | Abnormally deep labels used to bury the real domain. |

### 2. Homographs & confusables — "those letters aren't what they look like"

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://раypal.com` | `homograph_skeleton_collision`, `mixed_script`, `confusable_char` | Cyrillic `р`/`а` rendered identically to Latin — reads as `paypal.com`. |
| `https://сһаѕе.com` (all-Cyrillic) | `homograph_latin_skeleton` | Non-Latin host whose confusable skeleton is **pure ASCII-Latin** (`chase.com`) — masquerades as an ASCII domain, no brand list needed. **Blocks.** |
| `https://g00gle.com` | `brand_homoglyph`, `ascii_homoglyph` | ASCII digit look-alikes (`00` → `oo`) folding exactly onto `google.com`. |
| `https://xn--abc.com/` | `punycode_malformed` | A punycode label that doesn't decode to a valid IDN. |
| any IDN | `normalization_delta`, `idna_mapping_ambiguity` | Flags that the Unicode form differs from the ACE/punycode form, or maps differently under IDNA2003 vs. UTS-46. |
| `https://wordpreß.com` | `brand_idna_collapse` | IDNA2003 reads this as exactly `wordpress.com` while UTS-46 — and the actual request — resolves `xn--wordpre-6va.com`. A validator still on transitional processing approves it as the brand. |
| `https://tİktok.com` | `brand_locale_collapse` | A Turkish/Azeri lowercase collapses `İ` to a plain ASCII `i`, so a validator under that locale reads exactly `tiktok.com` while the request reaches `xn--tiktok-qyd.com`. |
| `https://münchen.de` (any genuine IDN) | `idn_host` | Internationalized (non-ASCII/punycode) domains are **blocked by default** (lands `high`). Set `idnPolicy: "allow"` or use `idnAllowlist` for IDN-legitimate deployments. |

### 3. Plain typosquatting — deliberately **not** detected

linklint answers one question: *does this string normalize to something other
than itself?* The brand watchlist exists only to **name** an anomaly that was
already found structurally — to sharpen "this label folds to something else"
into "…and that something else is `paypal.com`". It is never allowed to *create*
a finding on its own.

`gogole.com`, `paypai.com`, `netflicks.com`, and `netfliz.com` are structurally
flawless: pure ASCII, single script, no digits, no fold — `normalize(input)`
equals `input`. They are suspicious only relative to knowing that `google`,
`paypal`, and `netflix` exist and are worth money. That is brand intelligence,
not URL structure, and it works for exactly the hand-picked names on a list and
no others. All four score `0.00`. `brand_lookalike`, `brand_soundsquat`, and
`brand_bitsquat` were deleted for this reason, alongside the earlier
`brand_in_path` and `brand_combosquat`.

What **is** caught is the structural half of the same attack: `g00gle.com` and
`paypa1.com` (§2) fold onto a brand via ASCII digit look-alikes, and
`сһаѕе.com` collides with one under UTS#39 skeletons.

### 4. Dangerous payloads, schemes & redirects

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `javascript:fetch("//evil.example")` | `dangerous_scheme` | `javascript:`/`data:`/`blob:`/`file:` can execute or embed content. |
| `https://invoice.zip/download` | `file_extension_tld` | `.zip`/`.mov` TLD masquerading as a downloadable file. |
| `https://files.example.com/invoice.pdf.exe` | `suspicious_extension` | Deceptive double-extension hiding an executable. |
| `https://example.com/login?next=https://evil.com/phish` | `open_redirect_param` | A redirect parameter carrying a cross-host URL. |

### 5. Hidden & smuggled characters

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://exa​mple.com` | `invisible_char` | Zero-width / invisible / control characters in the URL. |
| filename with U+202E | `bidi_override` | RTL override flips `gpj.exe` to render as `exe.jpg`. |
| `http://127.0.0.1:6379/%0D%0ASLAVEOF` | `control_char` | Encoded CRLF/TAB/NUL used for protocol smuggling. |
| `https://example.com%2F@evil.com` | `encoding_obfuscation` | Percent-encoding hiding structural characters or nested decoding. |

## What linklint does not do

linklint makes one claim, deliberately narrow: **a URL is structurally anomalous.**
Its detectors answer "is something about this string malformed, disguised, or
inconsistent with how URLs normally work?" — a question that can be settled from the
string itself, offline and deterministically.

It does **not** claim to know which words are brands, which brands get phished, or
what a site does. That would be a semantic judgment, and it is out of scope by
design rather than by omission.

The clearest way to see the line:

```ts
inspect('https://paypa1.com');       // score 0.84 — '1' folds to 'l'; the string is disguised
inspect('https://paypal-login.com'); // score 0.0 — every label is a real, correctly
                                     //             spelled word in a normal arrangement
```

The second URL is very likely phishing. linklint returns `0.00` anyway, and that is
**correct behavior for what it claims**: there is nothing structurally wrong with the
string. Calling it deceptive requires knowing that PayPal is a brand worth
impersonating — knowledge linklint does not have and does not pretend to.

linklint does ship a small brand watchlist, but it is held to a strict rule: **the
watchlist may only be consulted to NAME a structural anomaly that was already
detected independently — it may never create a finding.** That is why
`paypa1.com` scores (a digit folds to a letter, and the list supplies the word
"PayPal" for the explanation) while `paypal-login.com` does not (nothing folds, so
there is nothing to name). Adding brands sharpens explanations; it never widens
coverage. The full statement of this boundary, with the reasoning and the
supporting literature, is [`docs/architecture.md` §1.1](./docs/architecture.md).

Concretely, linklint is not:

- **A phishing oracle.** `score: 0` means "no structural anomaly found," **not**
  "this link is safe." Never present a zero as a safety certificate to a user.
- **A threat feed or reputation service.** It checks no blocklists and has no notion
  of a site's history. A brand-new malicious domain and a decade-old benign one that
  are structurally identical score identically.
- **A malware or content scanner.** It never fetches the URL, so it cannot know what
  is served there. The core opens no network connections at all.
- **A replacement for the rest of your defenses.** It is one cheap, explainable,
  offline signal to compose with others — not a perimeter.

### Known gaps

Detection coverage is a bounded claim, so we track where the boundary currently sits
further in than it should. The largest such gap — a brand fold joined to another
token by a hyphen, where `paypa1.com` scored but `paypa1-login.com` returned `0.00`
— has since been closed: the brand-fold check now also tokenizes host labels on `-`,
so `paypa1-login.com` scores `0.80`/`high`. `paypal-login.com` still scores `0.00`,
and that is the scope boundary above, not a gap.

Known misses are committed as an executable corpus at
`packages/core/test/corpus/embarrassment.ts`, asserted so that they turn the build
red the moment they start being caught. Reports of further false negatives are
welcome as ordinary issues — see [SECURITY.md](./SECURITY.md#scope) for why they are
issues rather than vulnerabilities.

## Scoring & severity

Reason weights aggregate with **probabilistic-OR** — order-independent and saturating
toward 1, never past it:

```
score = 1 − ∏ (1 − wᵢ)
```

For example, `userinfo_present` (0.5) + `mixed_script` (0.4) →
`1 − (1−0.5)(1−0.4) = 0.7` → **high**.

| Severity | Score range |
|----------|-------------|
| `info` | `0` |
| `low` | `(0, 0.25]` |
| `medium` | `(0.25, 0.5]` |
| `high` | `(0.5, 0.8]` |
| `critical` | `(0.8, 1]` |

Informational reasons (e.g. `normalization_delta`, `confusable_char`) have weight `0`
and never change the score on their own — they add context. Weights and data sources
are **version-pinned** (`dataVersions` on every result), which records what a verdict
was computed against. Reproducing a verdict means pinning the package version —
detector logic is versioned there, not in `dataVersions`.

> A parsed URL with zero scoring weight is benign (`score: 0`). **Invalid** input is
> _not_ benign — it returns `score: null`, `severity: null`, and you should treat it
> with suspicion.

## The result contract

`inspect()` returns a stable, versioned object:

```ts
interface InspectResult {
  schemaVersion: '1.11';
  status: 'ok' | 'invalid';
  input: string;
  parsed: ParsedUrl | null;        // scheme, userinfo, registrableDomain, publicSuffix,
                                   // subdomain, hostLabels, port, path, query, fragment, isIp …
  score: number | null;            // [0,1] when ok; null when invalid
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | null;
  confidence: number;              // [0,1], independent from score
  reasons: Reason[];               // { code, layer, detail, weight }
  confusables: Confusable[];       // per-character expansion of confusable findings
  checksRun: string[];             // e.g. ['lexical', 'policy']
  checksSkipped: string[];         // e.g. ['resolution', 'reputation']
  dataVersions: DataVersions;      // pinned PSL / confusables / scripts / IDNA / brands / weights
  pslSnapshot: PslSnapshot;        // PSL observation date + advisory staleness
  enrichment?: EnrichmentReport;   // inspectAsync() only; versioned source outcomes/evidence
}
```

> **Gating? `status: "invalid"` must be checked separately — a numeric gate fails open.**
> `score` is `null` whenever `status` is `"invalid"`, and structural scans emit real
> scoring weight on inputs that then fail to parse: `http://169.254.169.254/` scores
> `0.75`, but the same host written with fullwidth dots is `invalid` / `score: null`
> while still carrying `separator_lookalike` (weight 0.5) — and still reaching the same
> cloud-metadata endpoint. Treat `invalid` as blocking:
> `if (r.status === 'invalid') block();` before comparing severity. See
> [`docs/scoring.md`](docs/scoring.md#gating-on-results--status-invalid-must-be-handled-explicitly)
> for the full predicate. The CLI (`--allow-invalid` opts out) and the MCP tool contract
> already fail closed this way.

`checksSkipped` makes the boundary explicit: today linklint runs the **lexical** layer
(and **policy**, if configured). When only lexical checks run, the score is a
**lower bound** — resolution and reputation layers are roadmap.

The full registry of reason codes lives in
[`docs/reason-codes.md`](./docs/reason-codes.md); the scoring model in
[`docs/scoring.md`](./docs/scoring.md); and the opt-in online evidence contract in
[`docs/enrichment-outcomes.md`](./docs/enrichment-outcomes.md).

`inspectAsync()` accepts a caller-ordered enrichment plan. Optional
`dependsOn: ['resolution:source-id']` edges create deterministic sequential
stages; independent sources still run in parallel, and downstream enrichers see
prior source-attributed outcomes through `context.previousOutcomes`. The runner
does not perform network I/O itself, and an empty/absent plan remains
byte-identical to `inspect()`. Every configured source is hard-bounded at 5
seconds by default without requiring a governor; a positive finite per-source
`timeoutMs` overrides the budget and `null` is the explicit opt-out. Provider,
cache, cache-key, and governor failures become machine-readable enrichment
outcomes and cannot reject the aggregate inspection.

Caching remains explicit and caller-owned. `EnrichmentCache` supports both
in-process and Promise-capable external stores; core writes only validated
structured reports and validates every hit again. Enrichers may use static
`cacheTtlMs` or choose a per-response lifetime with
`cacheTtlMsFor(report, context)`, including shorter negative-cache TTLs for
explicit `no-hit` outcomes. Skipped, failed, and partial reports are never
cached. Caller cache keys are schema/source-namespaced and must use a
privacy-safe projection rather than a full URL. See the caching contract and
migration examples in [`docs/enrichment-outcomes.md`](./docs/enrichment-outcomes.md).

## Policy layer — caller-configurable allow/deny

Beyond deception detection, callers can enforce their own org-specific rules. Policy
reasons annotate on a **separate channel** (`layer: 'policy'`, weight `0`) — they
**never change the deception score**, so detection and policy stay decoupled.

```ts
inspect('https://shop.example.ru/', { denyTlds: ['ru'] });
// → reasons: [{ code: 'tld_denied', layer: 'policy', detail: "TLD '.ru' is on the caller deny-list", weight: 0 }]
//   checksRun: ['lexical', 'policy']
```

Available options (all optional, all default-allow):

| Option | Effect |
|--------|--------|
| `allowTlds` / `denyTlds` | TLD allow-list (lockdown) or deny-list |
| `allowHosts` / `denyHosts` | Registrable-domain allow/deny (covers subdomains) |
| `allowSchemes` / `denySchemes` | Scheme allow/deny (e.g. lock to `https`) |
| `denyPorts` / `denyNonStandardPorts` | Block specific or non-standard ports |
| `maxDecodeDepth` | Bound recursive percent-decoding (decode-bomb guard) |

## MCP server — check before you fetch

linklint ships a thin, **local-only** [Model Context Protocol](https://modelcontextprotocol.io)
server so an LLM agent can vet a URL _before_ opening it.

```jsonc
// e.g. Claude Desktop / any MCP client config
{
  "mcpServers": {
    "linklint": { "command": "npx", "args": ["-y", "@linklint/mcp"] }
  }
}
```

It exposes two tools, both delegating to the same offline `inspect()` by default:

- **`check_url`** — check a URL before fetching: `{ url, agentMode? }`.
- **`check_domain`** — same verdict logic, for hostname-oriented callers:
  `{ domain, agentMode? }`.

`agentMode` is explicit and defaults to `false`; default MCP output is
byte-identical to `inspect(url)` and disabled agent checks are not listed as
skipped. Set `agentMode: true` for LLM/tool-use contexts to enable the
agent-gated V4 checks plus cloud-metadata SSRF escalation.

No network, no API keys — the server runs entirely on the local machine.

## CLI — check a URL from the shell

linklint ships a thin, offline command-line wrapper around the same `inspect()`.

```sh
npm install -g @linklint/cli   # or: npx @linklint/cli check <url>
```

```sh
linklint check https://раypal.com          # inspect one or more URLs
linklint check                              # read URLs from stdin (one per line) when piped
linklint batch urls.txt                     # inspect URLs from a file (one per line)
```

Files and stdin skip blank lines and lines starting with `#`.

| Flag | Effect |
|------|--------|
| `--json` | Emit a JSON array of full `InspectResult` objects (no human text) |
| `--fail-on <severity>` | Exit non-zero at/above this severity (`info`\|`low`\|`medium`\|`high`\|`critical`; default `high`) |
| `--allow-invalid` | Treat unparseable URLs as a pass (default: fail) |
| `--agent` | Enable the 4 agent-gated detectors (prompt-injection, credential-harvesting, data-exfiltration, cloud-metadata SSRF escalation) |
| `--allow-idn` | Permit internationalized (Unicode/punycode) domains (default: block at `high`) |
| `--idn-allow <domain>` | Exempt one registrable domain from the IDN block; repeatable |
| `--quiet` | One line per URL |
| `--no-color` | Disable ANSI color |
| `--offline` | Reserved no-op in v1 (accepted and ignored) |
| `--help` / `--version` | Print help / version and exit |

**Policy flags** are caller-supplied judgment, reported at weight `0`: they
annotate the verdict and never move the deception score. linklint ships no
built-in high-abuse TLD, host or port list, so this is where that judgment
lives. Each is the CLI form of the identically-named `inspect()` option, and
every `<value>` flag is repeatable.

| Flag | Effect |
|------|--------|
| `--deny-tld <tld>` | Report `tld_denied` for this TLD |
| `--allow-tld <tld>` | Report `tld_not_allowlisted` for any other TLD |
| `--deny-host <host>` | Report `host_denied` for this registrable domain (covers its subdomains) |
| `--allow-host <host>` | Report `host_not_allowlisted` for any other registrable domain |
| `--deny-scheme <scheme>` | Report `scheme_denied` for this scheme (e.g. `javascript`) |
| `--allow-scheme <scheme>` | Report `scheme_denied` for any other scheme (e.g. an https-only policy) |
| `--deny-port <port>` | Report `port_denied` for this explicit port; the value must be an integer `0`–`65535` |
| `--deny-non-standard-ports` | Report `port_denied` for any explicit port that is not the scheme's default |

```sh
linklint check --deny-host bit.ly https://bit.ly/3xAmPl3
linklint check --allow-scheme https --deny-non-standard-ports https://vendor.io:8443/
```

Exit codes: `0` all URLs below the `--fail-on` threshold and none invalid (or allowed),
`1` any URL at/above the threshold or any invalid URL (unless `--allow-invalid`), `2` usage error.

No network, no API keys — the CLI runs entirely on the local machine.

## Privacy & guarantees

- **No network** — nothing about the URL is ever transmitted.
- **No telemetry, no runtime file I/O** — pure, in-process computation.
- **Deterministic** — same input + same package version → same verdict, with no
  state carried between calls. The package version is the pin that matters:
  `dataVersions` on the result stamps the data snapshots, not detector logic.
- **Safe on untrusted input** — `inspect()` never throws; malformed input is reported,
  not crashed on. Unconditionally: even a non-string argument returns `invalid`.

## Repository layout

This is a pnpm monorepo.

| Path | What |
|------|------|
| `packages/core` | The `linklint` npm package — source of truth (`inspect()`, 37 detectors, scoring, policy, schema). |
| `packages/cli` | `@linklint/cli` — the offline `linklint` command-line wrapper (`check` / `batch`). |
| `packages/mcp` | `@linklint/mcp` — the local-only MCP server (`check_url` / `check_domain`). |
| `docs/architecture.md` | System architecture (channels, pipeline, result contract, layers). |
| `docs/reason-codes.md` | The full reason-code registry, with explanations. |
| `docs/scoring.md` | Version-pinned scoring model and severity bands. |
| `docs/guarantees.md` | Every unconditional claim in these docs, and the test pinning it. |
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

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [SECURITY.md](./SECURITY.md).

## Status & roadmap

**v1 — implemented.** The lexical layer is complete: 37 offline, deterministic detectors,
probabilistic-OR scoring, a caller-configurable policy layer, a stable versioned schema,
and a local MCP server. Typically < 5 ms per call, zero network.

**Online foundation, safe transport, and local wrapper decoding implemented.** The
opt-in `inspectAsync()` contract now includes versioned structured evidence,
staged orchestration, bounded degradation, and Promise-capable dynamic caching.
Core still performs no network I/O. The separate Node-only
`@linklint/online/transport` subpath provides exact-URL authorization, DNS
pinning, original-host TLS validation, credential stripping, and mandatory
budgets. `@linklint/online/resolution` locally decodes exact, version-pinned
Microsoft Safe Links and Proofpoint URL Defense wrappers and re-inspects every
recovered target offline without calling a vendor or destination service.

The next concrete layers are:

- **Resolution** — follow redirects / expand shorteners (opt-in, network).
- **Reputation** — check against threat feeds.

Both extend `checksRun` / `checksSkipped` and structured evidence without
replacing the offline verdict. The deterministic zero-I/O transport harness,
L0 boundary, and L2 local wrapper decoder are shipped; bounded
redirect/refresh expansion is the next Epic L frontier. See
[`docs/online-roadmap.md`](./docs/online-roadmap.md),
[`docs/online-composition-root.md`](./docs/online-composition-root.md),
[`docs/online-runtime-boundary.md`](./docs/online-runtime-boundary.md),
[`docs/safe-transport.md`](./docs/safe-transport.md),
[`docs/wrapper-decoding.md`](./docs/wrapper-decoding.md), and
[`docs/architecture.md`](./docs/architecture.md).

## License

[MIT](./LICENSE) © 2026 Bart Turczynski
