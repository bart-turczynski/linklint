# linklint architecture

## 1. Intent

linklint is an offline-first URL inspection engine: synchronous, deterministic, zero-network, never throws. Every verdict is explainable — each `InspectResult` carries named reason codes with weights and human-readable `detail` strings.

The core architectural rule: **channels do not implement detectors.** `packages/core` owns everything that affects a verdict; `packages/mcp` and `packages/cli` are thin adapters that call `inspect()` and present or enforce the result.

## 2. Repository layout

```
linklint/
  packages/
    core/           # linklint npm package — inspect(), 37 checks, scoring, policy, schema
    mcp/            # @linklint/mcp — local-only MCP server (check_url / check_domain)
    cli/            # @linklint/cli — offline CLI (linklint check / batch)
    online/         # @linklint/online — Node/server safe transport + deterministic fixtures
  docs/
    architecture.md
    online-runtime-boundary.md # Accepted ownership/packaging decision for online work
    safe-transport.md # L0 authorization, pinning, budget, and outcome contract
    redirect-chain-resolution.md # L1 redirect/refresh authorization and evidence
    reason-codes.md # Full reason-code registry with detection logic and examples
    scoring.md      # Scoring model, severity bands, weights table (v1.3)
    locale-case-mapping.md # Locale-tailored case mapping audit (the Turkish-I class)
  features/         # Cucumber behavioral specs (critical path + acceptance criteria)
  tools/            # Data-build scripts (confusables table generation)
```

## 3. Core package

`packages/core` is the source of truth. Public entry points:

| Export | What |
|--------|------|
| `linklint` | Stable `inspect()`, schema types, `InspectOptions`; legacy advanced compatibility re-exports |
| `linklint/metadata` | Reason-code metadata, scoring weights, and data-version stamps |
| `linklint/experimental` | Unstable detector, policy, parser, and unicode APIs |
| `linklint/data` | Version-pinned reference data (risky TLDs, brands, confusables) |

All exports are synchronous and side-effect-free. No network, no filesystem I/O at runtime.
New advanced consumers should prefer the secondary entry points over root
compatibility exports.

Runtime dependencies: `tldts` (Public Suffix List) and `tr46` (IDNA/UTS-46).

## 4. Inspection pipeline

`packages/core/src/inspect.ts` orchestrates these stages in order:

1. **Input preparation** — trim whitespace, preserve original input, accept full URLs or bare hostnames. Bound all recursive decoding to prevent decode-bomb CPU paths.

2. **Structural scans** — control chars, invisible chars, bidi overrides, separator lookalikes are checked before parsing (these can't rely on the parser to surface them).

3. **Parsing** — produce canonical components: scheme, userinfo, host (labels, registrable domain, public suffix), port, path, query, fragment. Use PSL for eTLD+1. Return `status: "invalid"` instead of throwing for unparseable input.

4. **Normalization** — IDNA/UTS-46 normalization via `tr46`. Record deltas as informational findings (`normalization_delta`).

5. **Detector execution** — run 37 independent lexical checks: 4 structural scans ahead of parsing, then 33 parsed-context detectors. The 5 agent-gated parsed detectors run only under `agentMode`. A detector failure adds `lexical:<id>` to `checksSkipped` rather than aborting the inspection. Any skipped scoring detector means the score is a lower bound, not a complete verdict.

6. **Policy layer** (optional) — apply caller-configured allow/deny rules. Policy reasons carry `weight: 0` and never change `score` or `severity`.

7. **Scoring** — aggregate scoring reasons with probabilistic-OR: `score = 1 − ∏(1 − wᵢ)`. Weights are version-pinned.

8. **Serialization** — return the stable `InspectResult` schema with `checksRun`, `checksSkipped`, `schemaVersion`, and `dataVersions`.

## 5. Detectors

`packages/core/src/detectors/` contains 37 lexical checks: 4 structural scans and 33 parsed-context detectors. Parsed detectors implement:

```ts
interface Detector {
  id: string;
  layer: 'lexical' | 'resolution' | 'reputation';
  run(context: InspectionContext): DetectorFinding[];
}
```

Detectors emit findings only — they never read weights. The core attaches weights from the version-pinned table (`packages/core/src/scoring/weights.ts`) keyed by reason code.

The 37 checks group into seven families (listed by **check id**; a single check
may emit several reason codes):

| Family | Detectors |
|--------|-----------|
| **Authority spoofing** | `userinfo_present`, `embedded_domain_in_subdomain`, `ambiguous_authority`, `ip_obfuscation`, `ip_classification`, `ambiguous_numeric_host`, `separator_lookalike`, `excessive_subdomain_depth` |
| **Homographs & confusables** | `mixed_script`, `confusable_char`, `ascii_homoglyph`, `punycode_malformed`, `normalization_delta`, `idna_mapping_ambiguity`, `locale_case_collapse`, `homograph_latin_skeleton`, `idn_host` |
| **Brand impersonation** | `brand_lookalike`, `brand_soundsquat`, `brand_bitsquat`, `homograph_skeleton_collision` |
| **Dangerous payloads** | `dangerous_scheme`, `file_extension_tld`, `suspicious_extension`, `open_redirect_param` |
| **Hidden characters** | `invisible_char`, `bidi_override`, `control_char`, `encoding_obfuscation`, `confusable_in_path` |
| **Contextual signals** | `risky_tld`, `bait_tokens` |
| **Agent-gated** | `prompt_injection_url`, `api_endpoint_impersonation`, `credential_harvesting`, `data_exfiltration`, `ssrf_cloud_metadata` |

Informational detectors (`confusable_char`, `confusable_in_path`, `normalization_delta`, `idna_mapping_ambiguity`, `locale_case_ambiguity`) have weight 0 — they annotate without raising severity. `idna_mapping_ambiguity` and `locale_case_ambiguity` each escalate to a weight-0.5 scoring code (`brand_idna_collapse`, `brand_locale_collapse`) when the alternate reading lands on a watchlist brand exactly.

## 6. Result schema

Every channel returns the same `InspectResult` (schema version `1.3`):

```ts
interface InspectResult {
  schemaVersion: '1.3';
  status: 'ok' | 'invalid';
  input: string;
  parsed: ParsedUrl | null;
  score: number | null;            // [0,1] when ok; null when invalid
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | null;
  confidence: number;              // [0,1]; 1.0 for deterministic lexical, min-aggregated across enrichers (FR-SCORE-2b)
  reasons: Reason[];               // { code, layer, detail, weight, suppressed? }
  confusables: Confusable[];
  checksRun: string[];             // e.g. ['lexical', 'policy']
  checksSkipped: string[];         // e.g. ['resolution', 'reputation']
  dataVersions: DataVersions;      // PSL, confusables, scripts, IDNA, brands, weights versions
  pslSnapshot: PslSnapshot;        // { date, stale } — provenance + advisory staleness of the PSL trust boundary (schema 1.2)
  enrichment?: EnrichmentReport;  // inspectAsync with configured work; versioned outcomes/evidence (schema 1.3)
}
```

Key invariants:

- `status: "invalid"` → `score: null`, `severity: null`, `parse_error` reason, `checksRun: []`. Invalid input is **not** benign.
- `score: 0` → `severity: "info"`. A parsed URL with zero scoring weight is benign even when informational reasons are present.
- `dataVersions` is present on both valid and invalid results for reproducibility.
- `pslSnapshot` (schema 1.2) is present on both valid and invalid results. `date` is the deterministic provenance date of the bundled PSL snapshot (the pinned `tldts` release date, a tight upper bound on the true list date); `stale` is an **advisory, time-relative** flag — the one field on the result that reflects wall-clock time — computed against a 180-day freshness window and `null` when the date is unknown. See §6.1.
- `enrichment` (schema 1.3) is present only when `inspectAsync()` receives configured enrichers. It contains independently versioned source outcomes/evidence and is absent from synchronous and empty-plan output.
- A non-empty `confusables[]` requires a corresponding `confusable_char` or `confusable_in_path` reason, and vice versa.
- If a lexical scoring detector fails, its ID appears in `checksSkipped` as `lexical:<id>`. The layer stays in `checksRun`; the score is a lower bound. Fail-closed consumers should treat results with `lexical:*` in `checksSkipped` as untrusted rather than benign.
- `confidence` is `1.0` for every deterministic lexical result (sync `inspect()`, including `status: "invalid"`). It is **independent** of `score`/`weight` and never feeds score aggregation; `inspectAsync()` lowers it to the **minimum** over the lexical base (`1.0`) and each successful probabilistic enricher finding's `confidence` (default `1.0`). With no enrichers it stays `1.0`, so `inspectAsync(url)` remains deep-equal to `inspect(url)`.
- `Reason.suppressed` is an OPTIONAL marker, present and `true` only when the caller's `suppressReasons` escape hatch (§8) matched that reason. It is **additive** and absent by default, so it needs no `SCHEMA_VERSION` bump: with no `suppressReasons` option every result is byte-for-byte identical to the pre-existing `1.1` output.

### 6.1 PSL snapshot provenance & staleness

linklint's core claim — "the real host is `evil.com`" — is computed from the
Public Suffix List bundled inside `tldts` (pinned via
`dataVersions.publicSuffixList`). A silently stale bundled PSL degrades
embedded-domain / brand-lookalike / ambiguous-authority reasoning with no signal
to callers, so the trust boundary carries its own provenance:

- **Provenance record** (`src/data/psl-provenance.ts`, `PSL_PROVENANCE`): a
  hand-captured `{ tldtsVersion, pslListDate, retrievedAt }` verified at
  dependency-pin time. `pslListDate` is the pinned `tldts` npm-release date used
  as the snapshot proxy — `tldts` regenerates its bundled list from upstream at
  release-build time, so the release date is a tight **upper bound** on the
  snapshot's age (staleness computed from it is conservative). Bump all three
  fields together with `dataVersions.publicSuffixList` on every `tldts` pin.
- **`pslOutdated(maxAgeDays = 180)`**: a **pure, offline** check reading only the
  provenance record → `{ stale, ageDays }`. Unknown/unparseable date →
  `{ stale: null, ageDays: null }` (undetermined, never assumed either way).
- **`result.pslSnapshot`**: `{ date, stale }` surfaced on every result so
  consumers learn the provenance of the boundary they were handed.
- **Freshness-corpus CI** (`test/freshness-corpus.test.ts`): pins the IMC '23
  (McQuistin et al., Table 2) multi-tenant eTLDs so a stale bundled PSL can never
  silently reintroduce the paper's tenant-collapse harm — two distinct tenants
  of `myshopify.com` etc. must not collapse to one registrable domain.

**Documented tradeoff — `allowPrivateDomains: false`.** `analyzeHost()`
(`parse/psl.ts`) resolves under ICANN-only rules **deliberately**, so an embedded
`github.io` is still seen as a registrable domain by FR-D-8. The consequence,
from the same IMC '23 paper, is that at the linklint layer private-suffix tenants
*do* collapse onto the ICANN registrable domain (`good.myshopify.com` and
`evil.myshopify.com` both resolve to `myshopify.com`). This is a conscious
tradeoff, **not** changed here; the freshness gate probes `tldts` with
`allowPrivateDomains: true` (the view where these eTLDs live) to test the bundled
*data's* freshness independently of that policy. A per-detector boundary choice
is a candidate follow-up.

## 7. Scoring

Probabilistic-OR aggregation over scoring reasons:

```
score = 1 − ∏(1 − wᵢ)
```

Order-independent and saturating toward 1. Severity bands:

| Severity | Score range |
|----------|-------------|
| `info` | `0` |
| `low` | `(0, 0.25]` |
| `medium` | `(0.25, 0.5]` |
| `high` | `(0.5, 0.8]` |
| `critical` | `(0.8, 1]` |

Weights are hand-tuned, version-pinned, and transparent. The full table is in `docs/scoring.md` and `packages/core/src/scoring/weights.ts`.

## 8. Policy layer

The policy layer answers "does this URL satisfy my org's allow/deny rules?" — a separate question from "is this URL deceptive?"

Policy reasons carry `layer: 'policy'` and `weight: 0`. They annotate the result without changing `score` or `severity`. `policy` appears in `checksRun` only when the caller configures at least one axis.

Available axes (all optional, all default-allow):

| Option | Effect |
|--------|--------|
| `allowTlds` / `denyTlds` | TLD allow-list or deny-list |
| `allowHosts` / `denyHosts` | Registrable-domain allow/deny |
| `allowSchemes` / `denySchemes` | Scheme allow/deny |
| `denyPorts` / `denyNonStandardPorts` | Port policy |
| `maxDecodeDepth` | Decode-bomb guard |

Enforcement is the consumer's job — linklint only reports the verdict. Ready-made
fail-closed wrappers (Claude Code PreToolUse hook, curl/wget shell aliases) live in
[`docs/enforcement.md`](enforcement.md).

### Caller false-positive escape hatch (`suppressReasons`)

`idnPolicy`/`idnAllowlist` let a caller say "non-ASCII here is fine" for the one
`idn_host` heuristic. `suppressReasons` generalizes that to **every** heuristic:
a caller supplies `{ code, host? }` rules marking a reason a false positive.

- **Annotate, don't delete.** A matched reason stays in `reasons[]` marked
  `suppressed: true`; its scoring `weight` is zeroed so `aggregate` ignores it and
  `score`/`severity` drop as if the signal were absent. linklint is never silently
  clean — the finding is still visible, just excluded from the verdict.
- **Scope.** No `host` = suppress that `code` for all inputs; a `host` limits it to
  inputs whose registrable domain matches (mirrors `idnAllowlist`: registrable
  domain, case-insensitive, Unicode/punycode agnostic, covers subdomains).
  Structured enrichment findings use their outcome's actual URL/host subject;
  allowing the original host never suppresses a discovered destination.
- **Honesty.** Whenever the option is present (even `[]`) the `suppression` token
  is appended to `checksRun` (order: `lexical → policy → agent → suppression`), so
  a result never hides that a caller escape hatch was applied.
- **Default-off.** With the option absent, output is byte-for-byte unchanged.
- **Both paths.** A single shared predicate (`scoring/suppress.ts`) is applied by
  sync `inspect()` (in `buildOkResult`, before sort/aggregate) and by
  `inspectAsync`'s re-aggregation, so enricher-layer reasons are equally
  suppressible.

## 9. Channels

| Package | Surface | npm name |
|---------|---------|----------|
| `packages/core` | `inspect()` library | `linklint` |
| `packages/mcp` | `check_url` / `check_domain` MCP tools (stdio) | `@linklint/mcp` |
| `packages/cli` | `linklint check` / `linklint batch` | `@linklint/cli` |
| `packages/online` | Explicit Node/server capabilities; L0 safe transport and L2 local wrappers shipped | `@linklint/online` |

Planned but not yet built: browser extension, GitHub Action, REST/serverless wrapper. The rule is the same for all of them: call `inspect()`, present the result, enforce policy at the adapter — never fork detector logic.

Concrete online work follows a stricter package boundary. Pure enrichment
contracts and orchestration remain in `linklint`; DNS-pinned destination
transport, resolution, provider adapters, and caller-owned mirror integrations
live in the Node-only `@linklint/online` sibling package; long-running
monitoring owns a separate deployable service and durable state. The existing
CLI and MCP packages remain offline, and browsers delegate authorized online
work to a caller-owned backend because browser fetch cannot enforce the L0
socket and DNS-pinning controls. The accepted decision, export categories,
dependency direction, consent, secret, licensing, and migration rules are in
[`online-runtime-boundary.md`](online-runtime-boundary.md).

The online package exposes L0 through `@linklint/online/transport`. Its
exact-URL authorization, all-answer address policy, DNS-pinned socket,
original-host TLS identity, fresh header set, manual redirects, cumulative
budgets, and structured outcomes are documented in
[`safe-transport.md`](safe-transport.md). The internal LT harness remains the
zero-external-network acceptance seam for resolver changes, connector identity,
streamed HTTP, failures, and deterministic deadlines.

Exact local Microsoft Safe Links and Proofpoint URL Defense decoding is exposed
through `@linklint/online/resolution`. It is separately bounded, never calls a
vendor decoder service, and re-inspects every recovered destination through the
offline pipeline. See [`wrapper-decoding.md`](wrapper-decoding.md).

The same subpath exposes bounded redirect and declarative-refresh expansion.
Every initial request and discovered target receives a separate caller
authorization decision and passes through one cumulative L0 session. Only
GET/HEAD and 301/302/303/307/308 are followed; HTTP Refresh and HTML meta refresh
share byte, MIME, charset, delay, and hop limits, and JavaScript is never
executed. Every target is inspected offline before the chain continues, ordered
hop evidence is retained, and only the worst fetched hop projects de-duplicated
findings. See [`redirect-chain-resolution.md`](redirect-chain-resolution.md).

## 10. Layer model

The three-layer model is a forward-compatibility contract:

| Layer | Status | Description |
|-------|--------|-------------|
| **Lexical** (L1) | **Implemented** | Offline, deterministic, synchronous. 37 checks: 4 structural, 33 parsed (5 of them agent-gated). < 5 ms typical. |
| **Resolution** (L2) | **Partial** | Exact local wrapper decoding and caller-authorized bounded redirect/refresh expansion are implemented; observed correlation/divergence and MIME evidence remain roadmap work. Every discovered target is re-inspected through L1. |
| **Reputation** (L3) | Roadmap | Threat feeds, RDAP domain age, CT, DNS posture. Privacy-preserving by design. |

L2 and L3 extend `checksRun` / `checksSkipped` — they add to lexical results,
never replace them. Unconfigured or incomplete sources remain explicit, so a
score never implies that unfinished resolution or reputation work was clean.

**Result cache (opt-in).** So networked enrichers don't re-hit third parties on every call, `inspectAsync` accepts a pluggable `EnrichmentCache`; `get`/`set` may be synchronous or Promise-capable, and `InMemoryEnrichmentCache` is the dependency-free default. Only runtime-validated structured reports are stored and every hit is revalidated. An enricher opts in with `cacheKey(result, context)` plus a positive static `cacheTtlMs`, a response-driven `cacheTtlMsFor(report, context)`, or both. Dynamic TTLs allow explicit no-hit results to use shorter negative-cache lifetimes; failures, skips, and partial reports are never cached. A hit skips the provider call but still counts as a run (`<layer>:<id>` in `checksRun`). **Privacy:** the framework never derives caller key material from the full URL, rejects direct full-URL leakage, and wraps the caller's projection in an opaque schema/source namespace. The adapter must still use a privacy-preserving projection (registrable domain, local-mirror ID, one-way hash-prefix), never reconstructible URL material.

**Bounded runner and per-source governor.** Every configured enricher is hard-bounded by the runner at 5000 ms by default, even when no governor is supplied. A positive finite `Enricher.timeoutMs` overrides the bound; `null` is the only explicit opt-out and is intended for callers with an outer hard deadline. Non-positive/non-finite values retain the safe default. Timeout aborts the composed context signal and wins a runner-level promise race even when an enricher ignores cancellation; the abandoned promise stays observed so a late rejection is handled. Promise-capable cache reads/writes are awaited behind the same source timeout policy and late rejections remain observed. `inspectAsync` also accepts an optional stateful `EnrichmentGovernor` (`InMemoryEnrichmentGovernor` is dependency-free with an injectable clock) for (1) a **token-bucket rate limit** and (2) **exponential backoff**, both keyed by `<layer>:<id>` and persisted when the instance is shared. The governor can additionally override/disable the timeout policy. Its built-in denial decisions distinguish `rate-limited` from `backoff-active`. **Ordering (cache-before-governor):** a cache HIT consumes no token and touches no backoff because no network happened; only a MISS is admitted, consuming exactly one token. All enricher, cache-key, dynamic-TTL, cache, and governor calls are guarded. Exceptions become source-attributed structured degradation outcomes rather than escaping `inspectAsync`; valid provider evidence is retained alongside auxiliary TTL/cache-write/governor-lifecycle failures, making partial coverage explicit in both `checksRun` and `checksSkipped`.

**Staged orchestration.** The caller-ordered `EnrichmentPlan` is the existing
`enrichers` list plus optional `Enricher.dependsOn` `<layer>:<id>` edges. The
runner derives stable topological stages: independent steps in one stage run in
parallel over the same prior-outcome snapshot, while fan-in waits until every
declared prerequisite wholly completes. `EnrichmentContext.previousOutcomes`
carries every earlier structured status in plan order. Skipped, failed, or
partial prerequisites produce an explicit `prerequisite-unavailable` skipped
outcome; invalid/duplicate edges and cycles also degrade explicitly. Final
serialization stays in caller plan order regardless of promise completion order.
No dependency declarations preserves the original single parallel stage.

## 11. Testing

Two runners:

- **Vitest** (`packages/*/test/`, `tests/`) — unit tests, corpus-driven detector tests, policy tests, public-API contract tests, performance baseline.
- **Cucumber** (`features/`) — behavioral specs: `inspect.feature`, `policy.feature`, `cli.feature`, `mcp_prefetch.feature`, `success_criteria.feature`.

Verify gate: `pnpm check` = `tsc --noEmit` + `vitest run` + `cucumber-js`. Pre-push hook and CI run the same gate.

Corpus vectors live in `packages/core/test/corpus/corpus.ts`. Labels: `deceptive`, `benign`, `info`, `invalid`. Per-row assertions on expected / forbidden reason codes.

## 12. Design invariants

- No network I/O in core or MCP.
- No telemetry.
- No native runtime dependencies.
- `inspect()` never throws — unparseable input returns `status: "invalid"`.
- Every finding has a named reason code with a human-readable `detail` string.
- Channels do not implement detectors.
- `normalization_delta`, `confusable_char`, and `confusable_in_path` are always informational (weight 0).
- Skipped lexical scoring detectors make the score a lower bound; fail-closed consumers must detect and handle `checksSkipped` entries matching `lexical:*`.
