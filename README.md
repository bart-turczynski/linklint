# linklint

> An explainable, offline-first, agent-native **URL inspector** — _"safe-chain for links."_

[![CI](https://github.com/bart-turczynski/linklint/actions/workflows/ci.yml/badge.svg)](https://github.com/bart-turczynski/linklint/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/linklint.svg)](https://www.npmjs.com/package/linklint)
[![Known Vulnerabilities](https://snyk.io/test/github/bart-turczynski/linklint/badge.svg)](https://snyk.io/test/github/bart-turczynski/linklint)
[![Socket Badge](https://socket.dev/api/badge/npm/package/linklint)](https://socket.dev/npm/package/linklint)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbart-turczynski%2Flinklint.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbart-turczynski%2Flinklint?ref=badge_shield)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/linklint)](https://bundlephobia.com/package/linklint)
[![node](https://img.shields.io/badge/node-%3E%3D24-3c873a.svg)](./packages/core/package.json)
[![types](https://img.shields.io/badge/types-included-3178c6.svg?logo=typescript&logoColor=white)](./packages/core/src/index.ts)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Hand **linklint** a single URL — from an email, a chat message, or an LLM agent's
tool call — and it tells you whether the URL is _deceptive_, and **explains exactly
why**, with no network and no data leaving the machine.

It generalizes one insight from hostname analysis: **if `normalize(input) !== input`,
something may be hiding in the URL.** linklint turns that intuition into 34 deterministic
detectors, each emitting a named, documented reason code (four — the agent-mode
prompt-injection, API-endpoint-impersonation, credential-harvesting, and data-exfiltration
detectors — are opt-in via `agentMode`).

```ts
import { inspect } from 'linklint';

inspect('https://paypal.com@evil.com/login');
// → severity: 'medium', score: 0.5, reasons: ['userinfo_present']
//   the real host is evil.com — "paypal.com" is just a username

inspect('https://раypal.com');
// → severity: 'high', score: 0.7
//   reasons: ['homograph_skeleton_collision', 'mixed_script', 'confusable_char', ...]
//   "раypal" is Cyrillic letters disguised as "paypal"

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
  (which is _not_ benign), so it is safe to call on fully untrusted strings.

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
r.score;     // 0.7         — [0,1], probabilistic-OR over detector weights
r.severity;  // 'high'      — 'info' | 'low' | 'medium' | 'high' | 'critical'
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

linklint runs **34 offline detectors** grouped into the families below (the agent-mode
prompt-injection, API-endpoint-impersonation, credential-harvesting, and data-exfiltration
detectors are opt-in via `agentMode` and off by default). Every example
is real output. A clean URL like `https://github.com` returns `score: 0`,
`severity: 'info'`, `reasons: []`.

### 1. Authority spoofing — "which host am I actually talking to?"

The most dangerous class: the URL _looks_ like it goes to a trusted host, but the real
authority is somewhere else.

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://paypal.com@evil.com/login` | `userinfo_present` | `paypal.com` is a **username** — the real host is `evil.com`. |
| `https://paypal.com.login.evil.tk/` | `embedded_domain_in_subdomain`, `risky_tld` | `paypal.com` is a **subdomain label**; the registrable domain is `evil.tk`. |
| `https://google.com#@evil.com` | `ambiguous_authority` | Fragment-in-authority — parsers disagree on the real host. |
| `http://2130706433/` | `ip_obfuscation`, `ip_loopback` | Decimal-encoded `127.0.0.1` — an IP wearing a disguise that resolves to loopback. |
| `http://169.254.169.254/` | `ip_cloud_metadata` | Literal cloud instance-metadata endpoint — the canonical SSRF credential-theft target. |
| `https://evil。com/` | `separator_lookalike` | `。` (U+3002) normalizes to `.` — a fake label separator. |
| `https://a.b.c.d.paypal.com.evil.tk/` | `excessive_subdomain_depth` | Abnormally deep labels used to bury the real domain. |

### 2. Homographs & confusables — "those letters aren't what they look like"

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://раypal.com` | `homograph_skeleton_collision`, `mixed_script`, `confusable_char` | Cyrillic `р`/`а` rendered identically to Latin — reads as `paypal.com`. |
| `https://g00gle.com` | `brand_homoglyph`, `ascii_homoglyph` | ASCII digit look-alikes (`00` → `oo`) folding exactly onto `google.com`. |
| `https://xn--abc.com/` | `punycode_malformed` | A punycode label that doesn't decode to a valid IDN. |
| any IDN | `normalization_delta`, `idna_mapping_ambiguity` | Flags that the Unicode form differs from the ACE/punycode form, or maps differently under IDNA2003 vs. UTS-46. |

### 3. Typosquatting & brand impersonation — "close, but not the real brand"

| Example | Reason code(s) | Why it's deceptive |
|---------|----------------|--------------------|
| `https://gogole.com` | `brand_lookalike` | Edit-distance 1–2 near-miss of a known brand. |
| `https://paypal-secure.com` | `brand_combosquat` | Brand keyword glued to a bait token. |
| `https://netflicks.com` | `brand_soundsquat` | Phonetic homophone of `netflix`. |
| `https://netfliz.com` | `brand_bitsquat` | Single-bit-flip neighbor of `netflix` (memory/DNS corruption squatting). |
| `https://evil.com/paypal.com/login` | `brand_in_path` | Brand name placed in the path of an unrelated host. |

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

### 6. Contextual low-weight signals

| Example | Reason code(s) | Why it's a signal |
|---------|----------------|-------------------|
| `https://promo.tk/` | `risky_tld` | High-abuse / free-registration TLD. |
| `https://secure-account-verify-login.com` | `bait_tokens` | Multiple stacked phishing-bait keywords. |

These carry low weight on their own — they're designed to **combine** with stronger
signals via the scoring model below.

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
are **version-pinned** (`dataVersions` on every result) so verdicts are reproducible.

> A parsed URL with zero scoring weight is benign (`score: 0`). **Invalid** input is
> _not_ benign — it returns `score: null`, `severity: null`, and you should treat it
> with suspicion.

## The result contract

`inspect()` returns a stable, versioned object:

```ts
interface InspectResult {
  schemaVersion: '1.0';
  status: 'ok' | 'invalid';
  input: string;
  parsed: ParsedUrl | null;        // scheme, userinfo, registrableDomain, publicSuffix,
                                   // subdomain, hostLabels, port, path, query, fragment, isIp …
  score: number | null;            // [0,1] when ok; null when invalid
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | null;
  reasons: Reason[];               // { code, layer, detail, weight }
  confusables: Confusable[];       // per-character expansion of confusable findings
  checksRun: string[];             // e.g. ['lexical', 'policy']
  checksSkipped: string[];         // e.g. ['resolution', 'reputation']
  dataVersions: DataVersions;      // pinned PSL / confusables / scripts / IDNA / brands / weights
}
```

`checksSkipped` makes the boundary explicit: today linklint runs the **lexical** layer
(and **policy**, if configured). When only lexical checks run, the score is a
**lower bound** — resolution and reputation layers are roadmap.

The full registry of reason codes lives in
[`docs/reason-codes.md`](./docs/reason-codes.md); the scoring model in
[`docs/scoring.md`](./docs/scoring.md).

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

It exposes two tools, both delegating to the same offline `inspect()`:

- **`check_url`** — check a URL before fetching.
- **`check_domain`** — same verdict logic, for hostname-oriented callers.

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
| `--quiet` | One line per URL |
| `--no-color` | Disable ANSI color |
| `--help` / `--version` | Print help / version and exit |

Exit codes: `0` all URLs below the `--fail-on` threshold and none invalid (or allowed),
`1` any URL at/above the threshold or any invalid URL (unless `--allow-invalid`), `2` usage error.

No network, no API keys — the CLI runs entirely on the local machine.

## Privacy & guarantees

- **No network** — nothing about the URL is ever transmitted.
- **No telemetry, no runtime file I/O** — pure, in-process computation.
- **Deterministic** — same input + same pinned data versions → same verdict.
- **Safe on untrusted input** — `inspect()` never throws; malformed input is reported,
  not crashed on.

## Repository layout

This is a pnpm monorepo.

| Path | What |
|------|------|
| `packages/core` | The `linklint` npm package — source of truth (`inspect()`, 34 detectors, scoring, policy, schema). |
| `packages/cli` | `@linklint/cli` — the offline `linklint` command-line wrapper (`check` / `batch`). |
| `packages/mcp` | `@linklint/mcp` — the local-only MCP server (`check_url` / `check_domain`). |
| `docs/architecture.md` | System architecture (channels, pipeline, result contract, layers). |
| `docs/reason-codes.md` | The full reason-code registry, with explanations. |
| `docs/scoring.md` | Version-pinned scoring model and severity bands. |
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

**v1 — implemented.** The lexical layer is complete: 31 offline, deterministic detectors,
probabilistic-OR scoring, a caller-configurable policy layer, a stable versioned schema,
and a local MCP server. Typically < 5 ms per call, zero network.

**Roadmap.** Two further layers are designed but not yet built:

- **Resolution** — follow redirects / expand shorteners (opt-in, network).
- **Reputation** — check against threat feeds.

Both will surface in `checksRun` / `checksSkipped` and contribute their own reason codes
on their own layers. See [`docs/architecture.md`](./docs/architecture.md).

## License

[MIT](./LICENSE) © 2026 Bart Turczynski
