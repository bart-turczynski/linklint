# linklint architecture

## 1. Intent

linklint is an offline-first URL inspection engine: synchronous, deterministic, zero-network, never throws. Every verdict is explainable — each `InspectResult` carries named reason codes with weights and human-readable `detail` strings.

The core architectural rule: **channels do not implement detectors.** `packages/core` owns everything that affects a verdict; `packages/mcp` and `packages/cli` are thin adapters that call `inspect()` and present or enforce the result.

## 2. Repository layout

```
linklint/
  packages/
    core/           # linklint npm package — inspect(), 35 checks, scoring, policy, schema
    mcp/            # @linklint/mcp — local-only MCP server (check_url / check_domain)
    cli/            # @linklint/cli — offline CLI (linklint check / batch)
  docs/
    architecture.md
    reason-codes.md # Full reason-code registry with detection logic and examples
    scoring.md      # Scoring model, severity bands, weights table (v1.3)
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

5. **Detector execution** — run 35 independent lexical checks: 4 structural scans ahead of parsing, then 31 parsed-context detectors. The 5 agent-gated parsed detectors run only under `agentMode`. A detector failure adds `lexical:<id>` to `checksSkipped` rather than aborting the inspection. Any skipped scoring detector means the score is a lower bound, not a complete verdict.

6. **Policy layer** (optional) — apply caller-configured allow/deny rules. Policy reasons carry `weight: 0` and never change `score` or `severity`.

7. **Scoring** — aggregate scoring reasons with probabilistic-OR: `score = 1 − ∏(1 − wᵢ)`. Weights are version-pinned.

8. **Serialization** — return the stable `InspectResult` schema with `checksRun`, `checksSkipped`, `schemaVersion`, and `dataVersions`.

## 5. Detectors

`packages/core/src/detectors/` contains 35 lexical checks: 4 structural scans and 31 parsed-context detectors. Parsed detectors implement:

```ts
interface Detector {
  id: string;
  layer: 'lexical' | 'resolution' | 'reputation';
  run(context: InspectionContext): DetectorFinding[];
}
```

Detectors emit findings only — they never read weights. The core attaches weights from the version-pinned table (`packages/core/src/scoring/weights.ts`) keyed by reason code.

The 35 checks group into seven families:

| Family | Detectors |
|--------|-----------|
| **Authority spoofing** | `userinfo_present`, `embedded_domain_in_subdomain`, `ambiguous_authority`, `ip_obfuscation`, `separator_lookalike`, `excessive_subdomain_depth` |
| **Homographs & confusables** | `mixed_script`, `confusable_char`, `ascii_homoglyph`, `punycode_malformed`, `normalization_delta`, `idna_mapping_ambiguity` |
| **Brand impersonation** | `brand_lookalike`, `brand_soundsquat`, `brand_bitsquat`, `homograph_skeleton_collision` |
| **Dangerous payloads** | `dangerous_scheme`, `file_extension_tld`, `suspicious_extension`, `open_redirect_param` |
| **Hidden characters** | `invisible_char`, `bidi_override`, `control_char`, `encoding_obfuscation`, `confusable_in_path` |
| **Contextual signals** | `risky_tld`, `bait_tokens` |
| **Agent-gated** | `prompt_injection_url`, `api_endpoint_impersonation`, `credential_harvesting`, `data_exfiltration`, `ssrf_cloud_metadata` |

Informational detectors (`confusable_char`, `confusable_in_path`, `normalization_delta`, `idna_mapping_ambiguity`) have weight 0 — they annotate without raising severity.

## 6. Result schema

Every channel returns the same `InspectResult` (schema version `1.1`):

```ts
interface InspectResult {
  schemaVersion: '1.1';
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
}
```

Key invariants:

- `status: "invalid"` → `score: null`, `severity: null`, `parse_error` reason, `checksRun: []`. Invalid input is **not** benign.
- `score: 0` → `severity: "info"`. A parsed URL with zero scoring weight is benign even when informational reasons are present.
- `dataVersions` is present on both valid and invalid results for reproducibility.
- A non-empty `confusables[]` requires a corresponding `confusable_char` or `confusable_in_path` reason, and vice versa.
- If a lexical scoring detector fails, its ID appears in `checksSkipped` as `lexical:<id>`. The layer stays in `checksRun`; the score is a lower bound. Fail-closed consumers should treat results with `lexical:*` in `checksSkipped` as untrusted rather than benign.
- `confidence` is `1.0` for every deterministic lexical result (sync `inspect()`, including `status: "invalid"`). It is **independent** of `score`/`weight` and never feeds score aggregation; `inspectAsync()` lowers it to the **minimum** over the lexical base (`1.0`) and each successful probabilistic enricher finding's `confidence` (default `1.0`). With no enrichers it stays `1.0`, so `inspectAsync(url)` remains deep-equal to `inspect(url)`.
- `Reason.suppressed` is an OPTIONAL marker, present and `true` only when the caller's `suppressReasons` escape hatch (§8) matched that reason. It is **additive** and absent by default, so it needs no `SCHEMA_VERSION` bump: with no `suppressReasons` option every result is byte-for-byte identical to the pre-existing `1.1` output.

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

Planned but not yet built: browser extension, GitHub Action, REST/serverless wrapper. The rule is the same for all of them: call `inspect()`, present the result, enforce policy at the adapter — never fork detector logic.

## 10. Layer model

The three-layer model is a forward-compatibility contract:

| Layer | Status | Description |
|-------|--------|-------------|
| **Lexical** (L1) | **Implemented** | Offline, deterministic, synchronous. 35 checks: 4 structural, 31 parsed, 5 agent-gated. < 5 ms typical. |
| **Resolution** (L2) | Roadmap | Follow redirects, expand shorteners, re-inspect each hop through L1. |
| **Reputation** (L3) | Roadmap | Threat feeds, RDAP domain age, CT, DNS posture. Privacy-preserving by design. |

L2 and L3 extend `checksRun` / `checksSkipped` — they add to lexical results, never replace them. Until they are built, the score is always a lower bound over L1 alone.

**Result cache (opt-in).** So networked enrichers don't re-hit third parties on every call, `inspectAsync` accepts a pluggable `EnrichmentCache` (`get`/`set` carrying a TTL; `InMemoryEnrichmentCache` is the dependency-free default). An enricher opts in per-source by declaring a `cacheKey(result)` and a positive `cacheTtlMs`; a cache hit skips the network call but still counts as a run (`<layer>:<id>` in `checksRun`). Failures and skips are never cached. **Privacy:** the cache key is entirely enricher-supplied — the framework never derives a key from the full URL, so an enricher must key on a privacy-preserving projection (registrable domain, hash-prefix), never the URL itself.

**Per-source governor (opt-in).** So one slow or failing source can never block a verdict, `inspectAsync` also accepts a pluggable `EnrichmentGovernor` (`InMemoryEnrichmentGovernor` is the dependency-free default, with an injectable clock; state persists across calls). It enforces three per-source mechanisms keyed by the `<layer>:<id>` token: (1) a **bounded timeout** — each `enrich` is raced against a per-source budget (`Enricher.timeoutMs`, else the governor default); on timeout the enricher's context signal aborts (`AbortSignal.any` of the caller's signal and a timer-driven one) and the source degrades to `checksSkipped`, and the runner-level race holds even if the enricher ignores its signal; (2) a **token-bucket rate limit** (capacity + continuous refill) — an out-of-tokens source is skipped, never queued or blocked; (3) **exponential backoff** — after consecutive failures a source is skipped without calling `enrich` until the (doubling, capped) window elapses, resetting on the first success. **Ordering (cache-before-governor):** the cache is consulted first — a HIT serves cached findings and consumes no token, starts no timeout, and touches no backoff, because no network happened. Only on a MISS is the governor consulted; a **token is consumed exactly at admission** (an attempted run), and any admitted run that does not cleanly succeed (timeout, throw/reject, post-abort, or a malformed return) records a failure for backoff and is never cached. With no governor supplied the pipeline behaves exactly as the pre-K4 path — governance is never on by default.

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
