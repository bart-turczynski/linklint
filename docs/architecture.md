# urlic architecture

> Status: draft v1 architecture
> Source: [PRD.md](../PRD.md), [IDEAS.md](../IDEAS.md), [IDEAS-ADDENDUM.md](../IDEAS-ADDENDUM.md)

## 1. Architectural intent

urlic is an offline-first URL inspection engine with multiple delivery channels. The core product
constraint is that every channel must return the same explainable verdict for the same input.

The architecture therefore separates:

- **Core inspection logic**: deterministic parsing, normalization, detectors, scoring, and schema.
- **Reference data**: version-pinned Unicode, Public Suffix List, and risky-TLD data.
- **Channel adapters**: MCP server, CLI, browser extension, CI action, REST wrapper, and future
  bindings.
- **Optional enrichments**: post-v1 network layers for resolution and reputation.

The most important design rule is: **channels do not implement detectors**. Channels only collect
input, call the core, and present or enforce the result.

## 2. Language and runtime choices

### 2.1 V1 default: TypeScript

Use **TypeScript** as the primary implementation language for v1.

Reasons:

- The PRD requires an npm core library and MCP server first.
- The v1 detector set is string, URL, Unicode, and table lookup work. It does not require native code.
- TypeScript can run in Node, browser extensions, edge runtimes, CI actions, and serverless wrappers.
- A shared type model prevents schema drift between library, MCP, CLI, and browser surfaces.
- Pure JS dependencies such as `tr46` and `punycode` satisfy the IDNA/UTS-46 requirement without
  native modules or WASM.

V1 should avoid Rust, Go, Python, and WASM in the hot path unless a specific package proves
unusable in JS. They add distribution and build complexity before there is a performance reason.

### 2.2 Later languages by channel

Post-v1 can add other languages without changing the product model:

| Channel | Preferred implementation | Rationale |
|---------|--------------------------|-----------|
| Core npm library | TypeScript | First-class JS/TS import path; browser and edge compatible. |
| MCP server | TypeScript on Node.js | MCP SDK support, direct core import, local-only process. |
| CLI | TypeScript on Node.js | Reuses core; easiest npm distribution. |
| Browser extension | TypeScript | Reuses core bundle; WebExtension APIs. |
| GitHub Action | TypeScript | Native action ecosystem and direct core import. |
| REST/serverless API | TypeScript | Thin wrapper over core; deploys to Node/edge runtimes. |
| Filter/feed generator | TypeScript initially | Same scoring and serialization; can move later if data scale demands. |
| Python bindings | Generated wrapper or WASM later | Only when non-JS users need local embedding. |
| Rust bindings | Separate native port or WASM later | Only for high-performance native consumers. |

WASM is intentionally **not** a v1 dependency. If later bindings need WASM, it should wrap a stable
core contract rather than become the primary implementation prematurely.

## 3. System shape

The project should be organized as a monorepo with a small core and thin channel packages:

```text
urlic/
  docs/
    architecture.md
    reason-codes.md
    scoring.md
  packages/
    core/
      src/
        index.ts
        inspect.ts
        parse/
        detectors/
        scoring/
        schema/
        data/
      test/
        corpus/
    mcp/
      src/
        server.ts
        tools/
    cli/
      src/
        main.ts
    browser-extension/
      src/
        background/
        content/
        popup/
    ci-action/
      src/
        main.ts
    rest/
      src/
        handler.ts
  tools/
    data-build/
    corpus/
  examples/
    node/
    mcp/
    browser/
```

V1 deliverables only need `packages/core` and `packages/mcp`, but reserving the package boundaries
early prevents the first implementation from becoming channel-shaped.

## 4. Core package

`packages/core` owns all behavior that affects a verdict.

Public API:

```ts
inspect(input: string, options?: InspectOptions): InspectResult
```

V1 must be synchronous. No detector in the default core path may perform network I/O, read from the
filesystem at runtime, start subprocesses, or depend on native modules.

### 4.1 Internal pipeline

The inspection pipeline should be explicit and stable:

1. **Input preparation**
   - Preserve the original input.
   - Trim surrounding whitespace.
   - Accept full URLs and bare hostnames.
   - Tolerate trailing junk where a useful URL/hostname can still be identified.
   - Bound all recursive decoding and normalization work so adversarial encodings cannot create a
     decode-bomb or unbounded CPU path.

2. **Parsing**
   - Produce canonical parsed components: scheme, userinfo, effective host, port, path, query,
     fragment, registrable domain, and host labels.
   - Use the Public Suffix List for eTLD+1.
   - Return `status: "invalid"` instead of throwing for unparseable input.

3. **Normalization**
   - Compute ACE and U-label forms through vetted IDNA/UTS-46 libraries.
   - Record normalization deltas as informational context.

4. **Detector execution**
   - Run lexical detectors independently.
   - Catch detector-local failures and add namespaced detector IDs such as `lexical:mixed_script` to
     `checksSkipped` rather than aborting inspection.
   - Treat a skipped scoring detector as a security-relevant condition: the resulting score is a lower
     bound, not a complete verdict.

5. **Scoring**
   - Apply version-pinned weights.
   - Aggregate scoring reasons with probabilistic OR:
     `score = 1 - product(1 - weight)`.
   - Keep informational reasons at `weight: 0`.
   - Attach reason weights from the version-pinned weights table keyed by reason code; detectors do
     not supply their own weights.

6. **Serialization**
   - Return the stable schema used by every channel.
   - Include `checksRun`, `checksSkipped`, `schemaVersion`, and data versions.

### 4.2 Detector interface

Detectors should be small units that receive a parsed inspection context and return findings.

```ts
interface Detector {
  id: string;
  layer: "lexical" | "resolution" | "reputation";
  run(context: InspectionContext): DetectorFinding[];
}
```

V1 detectors all use `layer: "lexical"`. Future network detectors should use the same shape but live
behind opt-in enrichers so they cannot accidentally enter the offline path.

### 4.3 V1 lexical detectors

The initial detector set maps directly to the PRD:

| Detector | Reason code | Scoring |
|----------|-------------|---------|
| Normalization delta | `normalization_delta` | Informational, weight 0 |
| Host confusables | `confusable_char` | Informational, weight 0 |
| Host script mixing | `mixed_script` | Scoring |
| Invisible/control chars | `invisible_char` | Scoring |
| Bidi overrides | `bidi_override` | Scoring |
| Userinfo authority deception | `userinfo_present` | Scoring |
| IP obfuscation | `ip_obfuscation` | Scoring |
| Embedded domain in subdomain | `embedded_domain_in_subdomain` | Scoring |
| Risky TLD | `risky_tld` | Low-weight scoring |
| Percent encoding obfuscation | `encoding_obfuscation` | Scoring |
| Dangerous scheme | `dangerous_scheme` | Scoring |
| Path/query confusables | `confusable_in_path` | Informational, weight 0 |

Detectors should emit findings only. The core maps findings to reason objects, attaches weights from
the version-pinned scoring table, orders reasons, and decides final severity.

## 5. Data ownership

Reference data is part of the reproducible verdict and must be version-pinned.

Core data sets:

- Public Suffix List snapshot.
- Unicode confusables data or curated high-risk subset.
- Unicode script/category tables needed by detectors.
- Risky TLD list.
- Scoring weights and severity bands.

The result schema should expose data versions so a verdict can be reproduced. `dataVersions` is
present on both `status: "ok"` and `status: "invalid"` results.

```ts
dataVersions: {
  publicSuffixList: string;
  unicodeConfusables: string;
  riskyTlds: string;
  weights: string;
}
```

For bundle size, large data should be isolated behind tree-shakeable entry points or generated compact
tables. The default `inspect()` path may load all v1 lexical data, but individual detector imports
should not force unrelated data into consumer bundles.

## 6. Result contract

All channels return the same `InspectResult`.

Top-level fields:

- `schemaVersion`
- `status`
- `input`
- `parsed`
- `score`
- `severity`
- `reasons`
- `confusables`
- `checksRun`
- `checksSkipped`
- `dataVersions`

`checksRun` and `checksSkipped` use explicit check IDs:

- Whole-layer IDs: `lexical`, `resolution`, `reputation`.
- Detector IDs when a layer partially ran but a detector did not complete:
  `lexical:<detector_id>`, for example `lexical:mixed_script`.

For a normal parsed v1 result, `checksRun` is `["lexical"]` and `checksSkipped` is
`["resolution", "reputation"]`. If the lexical layer ran but one detector failed, the layer remains
listed in `checksRun` and the failed detector is added to `checksSkipped`, for example
`["lexical:mixed_script", "resolution", "reputation"]`.

Any skipped lexical scoring detector means the score is a lower bound over the detectors that
completed. Fail-closed consumers should treat that verdict as untrusted instead of treating a low
score as benign.

`confusables` is a structured expansion of the confusable reasons:

- Every `confusables[]` entry must include `component` with `host`, `path`, or `query`.
- A non-empty `confusables[]` block requires a corresponding `confusable_char` or
  `confusable_in_path` reason.
- A `confusable_char` or `confusable_in_path` reason requires corresponding entries in
  `confusables[]`.

Invalid input is not benign:

- `status: "invalid"`
- `parsed: null`
- `score: null`
- `severity: null`
- `parse_error` reason
- `checksRun: []`
- `checksSkipped: ["lexical", "resolution", "reputation"]`
- `dataVersions` still present

Parsed input with zero scoring weight is benign, even if informational reasons are present:

- `status: "ok"`
- `score: 0`
- `severity: "info"`

## 7. Channel adapters

### 7.1 npm core library

The npm package is the source of truth for local embedding. It exports:

- `inspect()`
- Type definitions for result schema and options.
- Detector exports for advanced consumers.
- Reason-code metadata for docs and UI surfaces.

### 7.2 MCP server

The MCP package should be a thin local process around `packages/core`.

Tools:

- `check_url`
- `check_domain` as an alias for hostname-oriented callers

The tool description must tell agents to call it before fetching untrusted URLs. The MCP server must
not perform outbound network I/O, telemetry, or hosted lookups in v1.

### 7.3 CLI

The CLI is roadmap, but the architecture should reserve it as a direct core wrapper:

- `urlic check <url>`
- `urlic batch <file>`
- `--json`
- `--offline`
- configurable non-zero exit threshold, defaulting to `severity >= high`

Batch mode should stream results and avoid global failure from one invalid URL.

### 7.4 Browser extension

The extension should reuse the core bundle and present annotations, not independent verdict logic.

Likely surfaces:

- Content script for passive link annotation.
- Popup for manual inspection.
- Optional interstitial for high-severity URLs.

The passive path should stay lexical-only unless the user explicitly enables network enrichment.

### 7.5 CI and GitHub Action

The CI adapter should scan files, extract candidate URLs, call the core, and report findings. It
should not mutate detector behavior for CI-specific policy. Policy belongs in adapter options:

- severity threshold
- allowlist
- fail or comment mode
- paths to scan

### 7.6 REST/serverless wrapper

A REST API, if added, should remain a serialization boundary around the same schema. The hosted
wrapper must not become required infrastructure for the local-first product. Network/reputation
features should use privacy-preserving lookups where possible.

### 7.7 Filter/feed generation

Filter lists are not a v1 verdict channel. They are a publication format for confirmed or monitored
bad destinations. Generation should consume core verdicts plus curated or opt-in network data, then
emit hosts/AdBlock-compatible formats.

## 8. Layer boundaries

urlic has three conceptual layers.

### 8.1 Layer 1: lexical

V1 only. Offline, deterministic, synchronous, private.

This layer can run in:

- npm consumers
- MCP server
- browser extension
- CLI
- CI
- serverless edge

### 8.2 Layer 2: resolution

Roadmap. Opt-in. Networked.

Capabilities:

- redirect-chain expansion
- shortener and wrapper unwrapping
- open-redirect parameter analysis

Layer 2 must feed every discovered URL back through Layer 1. Its output should extend
`checksRun`/`checksSkipped`, not replace lexical results.

### 8.3 Layer 3: reputation and infrastructure

Roadmap. Opt-in. Networked or locally mirrored.

Capabilities:

- RDAP/domain age
- Safe Browsing/hash-prefix feeds
- URLhaus/PhishTank/OpenPhish style feeds
- TLS and Certificate Transparency
- DNS and hosting posture

Layer 3 should prefer local mirrors, hash-prefix queries, or k-anonymity patterns so a checked URL is
not exposed by default.

## 9. Use-case mapping

| Use case | Channel | Required layer | Policy |
|----------|---------|----------------|--------|
| Developer validates a submitted URL | npm core | Lexical | Caller decides reject/allow threshold. |
| Agent checks before fetch | MCP | Lexical | Agent should avoid fetching high/critical results. |
| CI scans docs/configs | CLI/GitHub Action | Lexical | Fail build at configured severity. |
| Human checks a pasted URL | CLI/browser popup/REST | Lexical now; optional enrichment later | Show reasons before action. |
| Browser annotates page links | Browser extension | Lexical passive | Do not phone home by default. |
| Brand monitoring | Feed generator/monitor | Resolution + reputation | Post-v1; opt-in network. |
| Non-JS embedding | Python/Rust binding | Lexical | Bind to stable schema after v1 settles. |

## 10. Testing strategy

Testing should be corpus-first because detector correctness is mostly about examples and edge cases.

Core test groups:

- Parser behavior for full URLs, bare hosts, malformed inputs, userinfo, ports, and schemes.
- Known-scoring deceptive examples for each v1 detector.
- Benign IDNs that must remain `score: 0`.
- Informational-only confusable and normalization cases.
- Percent-encoding recursion and bounded decode behavior.
- Public Suffix List eTLD+1 examples.
- Schema snapshots for ok, benign-with-info, deceptive, and invalid results.

Channel tests should verify adapter behavior only:

- MCP tool calls return the core schema.
- CLI exit codes match severity policy.
- Browser/CI adapters call the same core and do not fork reason logic.

Performance tests should assert the v1 synchronous `inspect()` path stays below the PRD target on a
representative corpus.

## 11. Implementation sequence

1. Create the TypeScript workspace and `packages/core`.
2. Define schema types, reason codes, scoring weights, severity bands, `docs/reason-codes.md`, and
   `docs/scoring.md`.
3. Implement parsing and invalid-result behavior.
4. Add PSL-backed registrable-domain extraction.
5. Implement lexical detectors one at a time with corpus tests.
6. Add data-version reporting.
7. Publish the core API shape and reason-code docs.
8. Add `packages/mcp` as a thin adapter over the core.
9. Add example integrations.
10. Reserve CLI/browser/CI package directories when those channels begin.

## 12. Design constraints to preserve

- No network I/O in v1 core or MCP.
- No telemetry in v1.
- No native runtime dependencies in v1.
- No thrown errors for arbitrary user input.
- No binary-only verdicts.
- No channel-specific detector forks.
- No scoring from `normalization_delta`, `confusable_char`, or `confusable_in_path` in v1.
- No dnstwist-style permutation generation in v1 core.
- A skipped lexical scoring detector means the score is incomplete; fail-closed consumers must be
  able to identify and distrust that verdict.
