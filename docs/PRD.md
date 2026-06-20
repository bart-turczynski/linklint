# linklint — Product Requirements Document

> **Status:** Draft v1 · **Date:** 2026-06-19
> **Source material:** [IDEAS.md](./IDEAS.md), [IDEAS-ADDENDUM.md](./IDEAS-ADDENDUM.md), and the
> competitive research from this session (dnstwist, urlscan.io, homograph extensions, Aikido safe-chain).

> **Historical note (read first):** This PRD captures the original product intent and is *not* a
> current implementation-status report. Some items it lists as roadmap have since shipped — notably
> the **CLI** (`@linklint/cli`), which is now an implemented surface. For the current architecture
> and what is actually built, see [`architecture.md`](./architecture.md) and the project README.

---

## 1. Overview

**linklint is a URL inspector.** Hand it a single, arbitrary URL — from an email, a chat message,
an LLM agent's tool call — and it tells you whether the URL is *deceptive*, and **explains exactly
why**, with no network and no data leaving the machine.

It grows out of the hostname transformer in `punycoder-online` and its founding insight: **if
`normalize(input) !== input`, something is hiding in the domain.** linklint generalizes that from
the hostname to the whole URL string.

### 1.1 The one-line positioning
> An explainable, offline-first, agent-native **URL verifier** — "safe-chain for links."

### 1.2 Why this exists (the gap)
Competitive research this session established that the inbound, single-URL, *explainable* direction
is underserved:

- **dnstwist** is **generative/outbound** — it takes a domain *you own* and enumerates impostors. It
  explicitly does **not** inspect an arbitrary given URL. (Opposite direction from linklint.)
- **Homograph browser extensions** are inbound but emit a **binary** "Unicode present!" alert — they
  false-positive on every legitimate IDN and never explain *which* character is the problem.
- **urlscan.io / CheckPhish / ScamAdviser** are **network-only, dynamic, public-by-default** sandboxes
  — heavy, privacy-exposing, and not embeddable as a fast local check.
- **Aikido safe-chain** proves the *interception* model (wrap the moment of action, block before harm,
  free/no-token/local-first feeds) — but operates on **package names, not URLs.**

linklint occupies the empty quadrant: **inbound + explainable + offline-first + embeddable.**

### 1.3 Non-goals (explicit)
- **Not a domain-permutation / brand-monitoring engine.** Typosquat *generation* is dnstwist's job;
  linklint **delegates** to it rather than reimplementing (see FR-DELEGATE).
- **Not a dynamic sandbox / page scanner.** No screenshotting, no content execution in v1 (urlscan's
  job).
- **Not a reputation/blocklist service** in v1. No phone-home threat-intel lookups in v1.
- **Not a consumer end-product** in v1. v1 targets developers and agents; the browser extension and
  ChatOps surfaces are roadmap.

---

## 2. Target users & primary use cases (v1)

**Primary audience: developers and AI agents.**

| User | Use case | Surface |
|------|----------|---------|
| Backend / app developer | Validate a user- or externally-supplied URL before storing, displaying, or fetching it | npm core library |
| CI / tooling author | Gate suspicious URLs in code, configs, docs | npm core (CLI is roadmap) |
| **LLM agent** (Claude Code, Cursor, custom) | Check a URL **before fetching** it — defend against prompt-injection links | **MCP server** |
| Agent platform author | Embed a fast, local, explainable URL check into an agent's tool surface | MCP server / npm core |

The agent pre-fetch case is the headline differentiator: there is no established offline, explainable
URL-safety primitive for agentic workflows.

---

## 3. Product principles

These are binding constraints, not aspirations. Every requirement below must honor them.

1. **Explainable over binary.** Never emit a bare boolean. Every verdict carries named, documented
   **reason codes** with human-readable detail ("Cyrillic U+0430 in a Latin label", not "suspicious").
2. **Offline-first.** The v1 core runs with **zero network**. It is deterministic and instant.
3. **Free, no-token, local-first.** No accounts, no API keys, no data leaves the machine (mirrors
   safe-chain's adoption model). Open-source.
4. **Honest about coverage.** A result must distinguish a parsed, checked, benign result (`status:
   "ok"` with zero scoring weight) from an invalid or not-checked result. The schema carries
   `checksRun` / `checksSkipped`.
5. **De-noise, don't over-flag.** "All non-ASCII = suspicious" is the failure mode of existing tools.
   Script-mixing and confusable-set analysis exist specifically to avoid flagging legitimate IDNs.
6. **Embeddable.** The core is a clean library first; every other surface consumes it.

---

## 4. The three-layer model & v1 boundary

linklint reasons about a URL in three layers. **v1 implements Layer 1 only.** Layers 2–3 are roadmap
(§8) and are named here so the architecture leaves room for them.

| Layer | Question | Network? | v1? |
|-------|----------|----------|-----|
| **1. Lexical** | Does the URL *look* deceptive on its face? | No | **✅ v1** |
| **2. Resolution** | Where does it actually *go* (redirects, shorteners, open redirects)? | Yes | Roadmap |
| **3. Reputation / infrastructure** | What's *known* about it (RDAP age, TLS/CT, feeds, DNS)? | Yes | Roadmap |

> **v1 network policy: none.** v1 performs **no** network I/O. RDAP domain-age — though the highest-signal
> single network check — is **roadmap**, not v1. This keeps v1 instant, private, and trivially embeddable.

---

## 5. Functional requirements — v1

### 5.1 Input handling

- **FR-IN-1** Accept a single URL or bare hostname as a string. Tolerate missing scheme, trailing
  junk, surrounding whitespace.
- **FR-IN-2** Parse into components: scheme, userinfo, host, port, path, query, fragment. Identify the
  **effective host** and the **registrable domain (eTLD+1)** via the Public Suffix List.
- **FR-IN-3** Never fetch, resolve, or execute the URL. Parsing only.
- **FR-IN-4** **Never throw on input.** A string that cannot be parsed as a URL/hostname returns a
  result with `status: "invalid"`, `parsed: null`, `score: null`, `severity: null`, a `parse_error`
  reason, `checksRun: []`, and `checksSkipped: ["lexical", "resolution", "reputation"]` — rather than
  raising. An `invalid` result means **"could not inspect," not "inspected and clean"**; consumers
  MUST NOT treat it as benign (a fail-closed caller should reject it). Inspection is total over
  arbitrary strings — it is a front-line security primitive and must not be DoS-able or crashable by
  malformed input.

### 5.2 Lexical detectors (Layer 1)

Each detector emits zero or more **reason codes**. All are offline and deterministic.

| ID | Detector | Reason code(s) | Origin |
|----|----------|----------------|--------|
| **FR-D-1** | **Punycode / normalization delta** — `normalize(host) !== host`; surface ACE ↔ U-label forms | `normalization_delta` | IDEAS core |
| **FR-D-2** | **Confusable annotation** — per-character, *which* char is confusable *with what* (Unicode confusables data) | `confusable_char` | IDEAS §1 |
| **FR-D-3** | **Script-mixing** — multiple scripts within one label (the IDN de-noiser) | `mixed_script` | IDEAS §2 |
| **FR-D-4** | **Invisible / zero-width / control chars** anywhere in the URL | `invisible_char` | IDEAS core |
| **FR-D-5** | **Bidi / RTL override** characters (U+202E etc.) anywhere in the URL | `bidi_override` | Addendum §1.5 |
| **FR-D-6** | **Userinfo / authority deception** — `paypal.com@evil.com`; surface the real host | `userinfo_present` | Addendum §1.1 |
| **FR-D-7** | **IP-address obfuscation** — decimal/octal/hex/dotless host; render canonical form | `ip_obfuscation` | Addendum §1.2 |
| **FR-D-8** | **Embedded domain in subdomain** — authority-looking domain appears left of the real eTLD+1, e.g. `paypal.com.spoof.info`; surface the real registrable domain | `embedded_domain_in_subdomain` | Addendum §1.3 |
| **FR-D-9** | **Dangerous / extension-confusable TLD** — `.zip`, `.mov`, high-abuse TLDs (contextual signal) | `risky_tld` | Addendum §1.4 |
| **FR-D-10** | **Percent-encoding obfuscation** — double-encoding, encoded structural chars; recursively decode (bounded) and re-check | `encoding_obfuscation` | Addendum §1.6 |
| **FR-D-11** | **Dangerous scheme** — `javascript:`, `data:`, `blob:`, `file:`, `vbscript:` | `dangerous_scheme` | Addendum §1.7 |
| **FR-D-12** | **Path/query homographs** — run FR-D-2/3/4 on path & query, not just host | `confusable_in_path` | Addendum §1.8 |

- **FR-D-13** Detectors run independently; a failure in one must not abort the others.
- **FR-D-14** FR-D-8 is purely lexical in v1: use the Public Suffix List to identify contiguous
  subdomain-label sequences that themselves look like registrable domains. Do **not** resolve the
  embedded domain in v1; DNS resolution is a Layer 2 roadmap enrichment.
- **FR-D-15** **FR-D-1 (`normalization_delta`) is informational-only and carries zero score weight.**
  Any IDN triggers it by definition, so on its own it must never raise severity — that is precisely the
  "all non-ASCII = suspicious" over-flagging that Principle 5 and SC-2 forbid. It is emitted as `info`
  context and only becomes meaningful in combination with a *scoring* detector (FR-D-3 script-mixing,
  FR-D-4 invisible chars, etc.). A single-script, all-confusable-free IDN (e.g. a legitimate
  `bücher.de`) must come back benign.
- **FR-D-16** **FR-D-2 / FR-D-12 (`confusable_char` / `confusable_in_path`) are informational-only
  (weight 0) in v1.** Raw confusable annotation alone must not score, or legitimate single-script IDNs
  (whose characters are individually "confusable" with Latin) would be penalized — the same SC-2
  failure mode. Confusables are *annotation*; the **score** for confusable-based deception comes from
  FR-D-3 `mixed_script` (cross-script confusion, the de-noising signal). Scoring a *single-script*
  whole-label homograph (e.g. an all-Cyrillic look-alike with no script mixing) requires a
  skeleton-collision policy against a comparison target — that needs a brand/skeleton index and is
  **roadmap**, not v1. v1 therefore *annotates* such a domain (info) but does not flag it; this
  limitation is documented, not a bug.

### 5.3 Scoring & output

- **FR-SCORE-1** Produce a **weighted, transparent risk score** in `[0, 1]` and a **severity**
  (`info` / `low` / `medium` / `high` / `critical`). Each scoring detector contributes a documented,
  hand-tuned weight `wᵢ ∈ [0, 1]` (the weights are the only tunable surface — see OQ-3).
- **FR-SCORE-1a** **Aggregation: probabilistic OR.** `score = 1 − Π(1 − wᵢ)` over all *scoring*
  reasons. This is order-independent, saturates toward 1 as signals stack, and never exceeds 1
  (so weights compose without a manual clamp). Informational-only reasons (FR-D-15/16) contribute `wᵢ = 0`
  and do not move the score. Worked example: `userinfo_present` (0.5) + `mixed_script` (0.4) →
  `1 − (0.5 × 0.6) = 0.7`. *(The earlier 0.92 figure was illustrative, not computed.)*
- **FR-SCORE-1b** **Severity bands** map from `score`: `info` = `0` · `low` = `(0, 0.25]` ·
  `medium` = `(0.25, 0.5]` · `high` = `(0.5, 0.8]` · `critical` = `(0.8, 1]`. Bands are documented and
  version-pinned alongside the weights.
- **FR-SCORE-2** The output is a structured object carrying a top-level `status` (`"ok"` for any input
  that parsed, `"invalid"` for unparseable input — see FR-IN-4), the parsed components, the
  `score`/`severity`, and the **ordered list of reasons** (each: `code`, `layer`, `detail`, `weight`
  — its score contribution; informational reasons carry `weight: 0`). Reasons are ordered by `weight`
  descending, then by detector ID.
- **FR-SCORE-2a** Per-character confusable findings appear in a top-level `confusables[]` block as a
  structured **expansion of** the confusable reason that surfaced them — the reason states *that* a
  confusable was found; `confusables[]` enumerates *which* (with a `component` field marking host vs
  path vs query). Whenever `confusables[]` is non-empty there is a corresponding `confusable_char`
  (FR-D-2, host) and/or `confusable_in_path` (FR-D-12, path/query) reason, and vice versa.
- **FR-SCORE-2b** **No `confidence` field in v1.** v1 detection is deterministic — a signal is either
  present or not — so a numeric confidence would be misleading. Detector reliability is instead encoded
  in the static `weight` (e.g. `risky_tld` is low-weight, `userinfo_present` high). A confidence field
  may be introduced only if/when probabilistic (Layer 2–3) signals arrive.
- **FR-SCORE-3** Output includes `checksRun` and `checksSkipped`. These arrays use layer IDs
  (`lexical`, `resolution`, `reputation`) for whole-layer status and may use namespaced detector IDs
  (`lexical:mixed_script`, `lexical:ip_obfuscation`, etc.) when a specific detector was expected but
  did not complete. For normal `status: "ok"` v1 results, all skipped checks are the Layer 2–3 network
  checks; `status: "invalid"` results skip lexical too because no parseable URL/hostname was available
  to inspect.
- **FR-SCORE-3a** If a scoring detector is skipped, the score is a **lower bound**, not a complete
  verdict. Fail-closed consumers should treat results with skipped lexical scoring detectors as
  untrusted rather than benign.
- **FR-SCORE-4** Stable, versioned JSON schema (`schemaVersion`). The MCP tool and library return the
  same shape.
- **FR-SCORE-4a** Output includes `dataVersions` for the version-pinned reference data and weights used
  to produce the verdict. `dataVersions` is present on both `status: "ok"` and `status: "invalid"`
  results so even parse failures are reproducible against the same parser/data release.
- **FR-SCORE-5** **Benign result shape.** A URL that parsed and triggered no *scoring* detector is
  **benign**: `status: "ok"`, `score: 0`, `severity: "info"`. Informational-only reasons (FR-D-15/16,
  e.g. a lone `normalization_delta` on a legitimate IDN, or `confusable_char` annotations) may be
  present and do **not** make the result non-benign — "benign" is defined by zero scoring weight, not
  by an empty `reasons` array. `checksRun`/`checksSkipped` are always populated so a benign `ok` result
  is never confused with an `invalid` (unchecked) one.

Reference schema (deceptive input):
```json
{
  "schemaVersion": "1.0",
  "status": "ok",
  "input": "https://paypal.com@xn--pypal-4ve.ru/login",
  "parsed": {
    "scheme": "https",
    "userinfo": "paypal.com",
    "effectiveHost": "xn--pypal-4ve.ru",
    "registrableDomain": "xn--pypal-4ve.ru",
    "port": null,
    "path": "/login"
  },
  "score": 0.7,
  "severity": "high",
  "reasons": [
    { "code": "userinfo_present",    "layer": "lexical", "detail": "authority hidden behind 'paypal.com@'", "weight": 0.5 },
    { "code": "mixed_script",        "layer": "lexical", "detail": "Cyrillic U+0430 in Latin label",        "weight": 0.4 },
    { "code": "confusable_char",     "layer": "lexical", "detail": "1 confusable character in host",         "weight": 0 },
    { "code": "normalization_delta", "layer": "lexical", "detail": "host is an internationalized domain (IDN)", "weight": 0 }
  ],
  "confusables": [
    { "char": "а", "codepoint": "U+0430", "confusableWith": "a (U+0061, LATIN SMALL LETTER A)", "component": "host", "position": 1 }
  ],
  "checksRun": ["lexical"],
  "checksSkipped": ["resolution", "reputation"],
  "dataVersions": {
    "publicSuffixList": "snapshot-2026-06-19",
    "unicodeConfusables": "uts39-16.0.0-curated",
    "riskyTlds": "2026-06-19",
    "weights": "1.0"
  }
}
```
Score: `1 − (1−0.5)(1−0.4) = 0.7` → `high`. `confusable_char` and `normalization_delta` are
informational (weight 0, per FR-D-15/16) and annotate without scoring — the cross-script signal that
actually scores this host is `mixed_script`.

Reference schema (invalid input — `status: "invalid"`, must not be read as benign):
```json
{
  "schemaVersion": "1.0",
  "status": "invalid",
  "input": "ht!tp://%%%not a url",
  "parsed": null,
  "score": null,
  "severity": null,
  "reasons": [
    { "code": "parse_error", "layer": "lexical", "detail": "input is not a parseable URL or hostname", "weight": 0 }
  ],
  "checksRun": [],
  "checksSkipped": ["lexical", "resolution", "reputation"],
  "dataVersions": {
    "publicSuffixList": "snapshot-2026-06-19",
    "unicodeConfusables": "uts39-16.0.0-curated",
    "riskyTlds": "2026-06-19",
    "weights": "1.0"
  }
}
```

### 5.4 Delegation (not reimplementation)

- **FR-DELEGATE-1** linklint does **not** implement domain-permutation generation. Where a "show me the
  known siblings of this domain" capability is wanted, it is provided as an **optional integration that
  shells out to / wraps dnstwist** — and is **roadmap, not v1**.

### 5.5 Deliverables — v1

#### A. Core library (npm, pure TypeScript)
- **FR-LIB-1** Pure TypeScript. **No WASM** in v1 (the lexical checks are data + string ops). Runs in
  Node, browser, and edge runtimes with no native glue. Note: while punycode encoding is trivial, the
  **UTS-46 / IDNA normalization** behind FR-D-1 is not — use a vetted pure-JS implementation
  (`tr46` / `punycode`), do not hand-roll it.
- **FR-LIB-2** Clean, typed, documented public API. A single **synchronous** `inspect(url, options?)`
  entry point (no Promise — v1 does no I/O, backing NFR-PERF-1) returning the FR-SCORE-2 object;
  individual detectors also exportable.
- **FR-LIB-3** Bundled, **version-pinned** data sets (Unicode confusables subset, Public Suffix List,
  risky-TLD list) — see NFR-DATA.
- **FR-LIB-4** Zero required runtime dependencies on **network or native modules** (pure-JS deps such as
  `tr46` are permitted).

#### B. MCP server
- **FR-MCP-1** Expose a `check_url` (and alias `check_domain`) tool over the MCP SDK that wraps the core
  library and returns the FR-SCORE-2 schema.
- **FR-MCP-2** Local-only (user runs it themselves). No outbound network, no telemetry.
- **FR-MCP-3** Tool description must make the **agent pre-fetch** use case explicit and instruct the
  agent to check untrusted URLs *before* fetching them.
- **FR-MCP-4** The egress-guard / interception variant (transparently block an agent's fetches) is
  **roadmap** (§8); v1 is the explicit `check_url` tool.

---

## 6. Non-functional requirements

- **NFR-PERF-1** A single `inspect()` call completes in < 5 ms on a typical dev machine (offline, no I/O).
- **NFR-PRIV-1** v1 makes **no** network calls and emits **no** telemetry. Nothing about the inspected
  URL leaves the process.
- **NFR-DATA-1** All reference data sets are **version-pinned**, and the version that produced a verdict
  is surfaced (reproducibility). Updates are deliberate, reviewed bumps.
- **NFR-DATA-2** Confusables data may be a **curated high-risk subset** rather than the full
  `confusables.txt` if that keeps bundle size reasonable (see OQ-1).
- **NFR-DATA-3** Bundle size matters for the browser/edge target. The Public Suffix List (~220 KB) and
  the confusables set dominate it. Ship the data behind a **separate, tree-shakeable entry point** (or
  lazy import) so consumers that only need a subset of detectors don't pay for all data.
- **NFR-TEST-1** Maintain a labeled **test corpus** of known-deceptive and known-benign URLs
  (incl. legitimate IDNs that must *not* over-flag) and measure precision/recall as detectors evolve.
- **NFR-DOC-1** Every reason code is documented (what it means, why it's a signal, example).
- **NFR-LICENSE-1** Open-source under the **MIT license** (resolves OQ-4). Free, no token, no account.

---

## 7. Success criteria (v1)

- **SC-1** **Scores (severity ≥ `medium`), with the right reason codes,** the canonical *scoring*
  attack set: script-mixed host, userinfo spoof, IP-obfuscated host, embedded-domain subdomain
  (`paypal.com.spoof.info`), bidi override, and `javascript:`/`data:` scheme.
- **SC-1a** **Annotates without over-scoring** the informational cases: a single-script IDN and a
  path-embedded confusable emit the correct `normalization_delta` / `confusable_char` /
  `confusable_in_path` reasons (weight 0) and return **benign** (`severity: "info"`) absent any scoring
  signal — per FR-D-15/16.
- **SC-2** Does **not** flag legitimate single-script IDNs as deceptive (the existing-extensions
  failure mode). Validated against the benign half of the test corpus.
- **SC-2a** Returns `status: "invalid"` (never a benign `ok`) for unparseable input, so a fail-closed
  consumer can reject it — per FR-IN-4.
- **SC-3** An LLM agent can call the MCP `check_url` tool and act on the structured verdict before
  fetching a URL.
- **SC-4** The library installs and runs in Node, browser, and edge with no extra setup.

---

## 8. Roadmap (post-v1)

Ordered to extend the layers and surfaces without reworking the core. Each item names the layer/surface
it unlocks.

### Phase 2 — Resolution (Layer 2) + first network enrichment
- Redirect-chain expansion (run every hop back through Layer 1).
- Link-shortener / wrapper unwrapping.
- Open-redirect parameter detection.
- **RDAP domain-age** enrichment (opt-in) — the "new domain + confusable" high-signal combo.

### Phase 3 — Reputation (Layer 3), privacy-preserving + CLI
- Blocklist/feed lookups (Safe Browsing, URLhaus, PhishTank/OpenPhish) via **k-anonymity hash-prefix**
  queries — full URL never sent.
- **CLI** surface: `linklint check` / `batch`, `--offline`, `--json`, non-zero exit on `severity >= high`.

### Phase 4 — Interception model (safe-chain–inspired)
- **Agent egress proxy** — transparently intercept and block deceptive URLs before an agent's fetch
  fires (the stronger form of FR-MCP-4).
- **Shell wrapping** — alias `curl`/`wget`/`git clone` to verdict-before-request.
- **CI shims** in PATH for pipeline URL gating.

### Phase 5 — TLS/CT + monitoring + distribution breadth
- TLS cert + Certificate Transparency (crt.sh) signals.
- **Monitoring mode**: stream CT logs / re-check permutations for a brand watchlist; auto-feed a
  **self-hostable JSON filter feed** (the safe-chain feed reframe; also a hosts/AdBlock format for
  Pi-hole / NextDNS / uBlock).
- **dnstwist integration** (FR-DELEGATE) for "known siblings."
- **Browser extension** (explainable annotation, interstitial block).
- **ChatOps bot**, **REST/serverless API**, **non-JS bindings** (Python/Rust).
- Content-level signals (favicon hashing, login-form analysis) — heavily sandboxed, opt-in.

---

## 9. Open questions

- **OQ-1** Confusables coverage: full Unicode `confusables.txt` vs. a curated high-risk subset for v1?
  (Bundle-size vs. coverage trade-off.)
- **OQ-2** Where does network live for the eventual browser extension — phone-home vs. backend vs.
  local-only? (Layer 2–3 in a passive content script has privacy implications the lexical scan doesn't.)
- **OQ-3** Scoring weights: the *aggregation function* is settled (probabilistic OR, FR-SCORE-1a) and
  the *bands* are set (FR-SCORE-1b); what remains open is how the per-detector **weight values** are
  chosen — hand-tuned & transparent (on-thesis, but arbitrary) vs. learned from the labeled corpus
  (better-calibrated, but a black box that undercuts "explainable"). v1 assumes hand-tuned.
- **OQ-4** ~~License choice (MIT / Apache-2.0 / other).~~ **Resolved: MIT** — permissive,
  conventional default for npm/OSS; see `LICENSE` and `packages/core/package.json`.
- **OQ-5** How much resolution (Phase 2) should ever be automatic? Following redirects *fetches*
  attacker-controlled URLs — in an agent context that may be the opposite of what you want. Likely
  explicit-opt-in, never default.
- **OQ-6** Sustainability: does the project stay pure-OSS/local-first indefinitely, or add an optional
  hosted tier later? (v1 posture is pure OSS/local-first; this is deferred, not decided.)
