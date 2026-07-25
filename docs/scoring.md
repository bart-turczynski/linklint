# Scoring

> Version-pinned (`dataVersions.weights`). Source of truth:
> `packages/core/src/schema/reason-codes.ts` (weights) and
> `packages/core/src/scoring/` (aggregation + bands). Current weights version:
> **1.12**.

## Aggregation — probabilistic OR (FR-SCORE-1a)

The risk score is computed over the **scoring** reasons only:

```
score = 1 − Π(1 − wᵢ)
```

Properties:

- **Order-independent** — the product does not depend on detector order.
- **Saturating** — stacking signals pushes the score toward 1 but never past it,
  so weights compose without a manual clamp.
- **Informational reasons contribute nothing** — their weight is 0, so
  `(1 − 0) = 1` leaves the product unchanged (FR-D-15/16).

Worked example: `userinfo_present` (0.5) + `ip_obfuscation` (0.4):

```
score = 1 − (1 − 0.5)(1 − 0.4) = 1 − 0.5 × 0.6 = 0.7 → high
```

A **blocker** weight (1.0) zeroes a factor and saturates the score: any URL with
`mixed_script`, `invisible_char`, `bidi_override`, or `homograph_latin_skeleton`
scores exactly 1 (critical), regardless of what else fires.

## Severity bands (FR-SCORE-1b)

| Severity   | Score range   |
| ---------- | ------------- |
| `info`     | `0`           |
| `low`      | `(0, 0.25]`   |
| `medium`   | `(0.25, 0.5]` |
| `high`     | `(0.5, 0.8]`  |
| `critical` | `(0.8, 1]`    |

A parsed input with zero scoring weight is **benign**: `score: 0`,
`severity: "info"` — even when informational reasons are present (FR-SCORE-5).
Invalid input has `score: null` / `severity: null` and is **not** benign.

### Gating on results — `status: "invalid"` must be handled explicitly

**The obvious gate fails open.** `score` is `null` whenever `status` is
`"invalid"`, so a numeric comparison silently lets those inputs through:

```ts
// WRONG — fails OPEN on every invalid result (null >= 0.7 is false).
if (result.score !== null && result.score >= 0.7) block();
if (result.score >= 0.7) block();   // same bug, TypeScript rejects it
```

This is not a theoretical edge. Structural scans run **before** parsing and do
emit scoring-weight findings on inputs that then fail to parse, so the weight is
real and is discarded:

| Input | `status` | `score` | Reasons (weight) |
|---|---|---|---|
| `http://169.254.169.254/` | `ok` | **0.75** | `ip_cloud_metadata` (0.75) |
| the same host with fullwidth dots `．` | `invalid` | **`null`** | `separator_lookalike` (**0.5**), `idna_mapping_ambiguity` (0) |
| `https:///evil.com` | `invalid` | **`null`** | `ambiguous_authority` (**0.65**) |

The first row is blocked by a numeric gate; the second reaches the identical
cloud-metadata endpoint and is not.

**The correct predicate** treats `invalid` as blocking in its own right:

```ts
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

function shouldBlock(result: InspectResult, failOn: keyof typeof RANK = "high") {
  // Fail CLOSED: unparseable input is "not checked", never "checked and clean".
  if (result.status === "invalid") return true;
  return RANK[result.severity!] >= RANK[failOn];
}
```

`packages/core/test/invalid-gate-contract.test.ts` pins both halves — that the
naive gate fails open on these exact inputs, and that this predicate does not.

Both shipped enforcement surfaces already do this: the CLI exits `1` on any
invalid result unless `--allow-invalid` is passed (`cli/src/policy.ts`, "an
invalid URL is never assumed safe"), and the MCP tool contract instructs callers
to treat `status: "invalid"` as not-checked.

**Why `score` stays `null` rather than carrying a lower bound.** Surfacing a
partial score for invalid results was considered and rejected: it would make
`score >= threshold` *sometimes* correct, which is worse than reliably wrong. A
`parse_error`-only result would carry a lower bound of `0`, so the naive gate
would still fail open on it while now appearing to work on the two rows above —
the bug would survive, harder to find. `null` forces the caller to confront the
contract once, and `status` is the field that answers "was this checked at all".

### Caller false-positive suppression (`suppressReasons`)

The `suppressReasons` option is a caller-owned escape hatch — the general form of
the single-heuristic `idnPolicy`/`idnAllowlist` opt-out, applied to **every**
reason code. Each rule marks a reason `code` a false positive, optionally scoped
to a registrable `host` (omitted host = all hosts; host matching mirrors
`idnAllowlist` — registrable-domain, case-insensitive, Unicode/punycode
agnostic). A matched reason **stays in `reasons[]`** annotated `suppressed: true`
but its `weight` is zeroed, so `aggregate` skips it and `score`/`severity` drop
exactly as if the signal were absent. Suppressing every scoring reason drives the
verdict to `score: 0` / `severity: "info"`.

Suppression never hides itself: whenever the option is present (even `[]`) the
`suppression` token appears in `checksRun`. With the option absent, output is
byte-for-byte unchanged — the `suppressed` marker never appears, so no
`SCHEMA_VERSION` bump is needed (the field is additive and absent by default).
Enricher-layer reasons (`inspectAsync`) are suppressible by the same mechanism.
For structured enrichment, host scope is evaluated against each finding's
outcome subject rather than the original input, so an exemption for the original
host cannot suppress evidence about a discovered destination. Legacy flat
findings retain their original-input subject.

## Weights table (v1, hand-tuned — OQ-3)

Weights are hand-tuned and transparent (not learned), so the verdict stays
explainable. Scoring reliability is encoded in the weight itself.

### The `confidence` field (FR-SCORE-2b)

Every result also carries a top-level `confidence` in `[0,1]`, **independent of
`weight` and `score`**: `weight` drives the deception score, `confidence` is a
separate advisory measure of how reliable the contributing signals are. It does
**not** feed the probabilistic-OR aggregation above.

- Deterministic lexical results — everything the synchronous `inspect()`
  produces, including `status: "invalid"` — are fully deterministic at
  `confidence: 1.0`.
- Probabilistic (resolution/reputation) enrichers run via `inspectAsync()` may
  express a per-finding `confidence`; omitting it means `1.0`.
- The result's `confidence` is the **minimum** over all contributing signals
  (the lexical base at `1.0` plus each successful enricher finding's
  confidence). A verdict is only as confident as its least-confident signal
  (fail-closed). A skipped/failed enricher contributes nothing — its absence is
  already visible in `checksSkipped`. With no enrichers, `confidence` stays
  `1.0`.

A weight of **1.00 is a blocker** — under probabilistic OR the `(1 − w)` factor
zeroes the product, so the score saturates to 1 (critical) regardless of any other
signal. Reserved for patterns with no legitimate use.

| Reason code                    | Weight | Scoring? |
| ------------------------------ | ------ | -------- |
| `mixed_script`                 | 1.00   | yes      |
| `invisible_char`               | 1.00   | yes      |
| `bidi_override`                | 1.00   | yes      |
| `homograph_latin_skeleton`     | 1.00   | yes      |
| `ssrf_cloud_metadata`          | 1.00   | yes (agent) |
| `dangerous_scheme`             | 0.90   | yes      |
| `ip_cloud_metadata`            | 0.75   | yes      |
| `idn_host`                     | 0.70   | yes      |
| `ambiguous_authority`          | 0.65   | yes      |
| `control_char`                 | 0.60   | yes      |
| `suspicious_extension`         | 0.50   | yes      |
| `separator_lookalike`          | 0.50   | yes      |
| `userinfo_present`             | 0.50   | yes      |
| `embedded_domain_in_subdomain` | 0.50   | yes      |
| `homograph_skeleton_collision` | 0.50   | yes      |
| `brand_locale_collapse`        | 0.50   | yes      |
| `brand_idna_collapse`          | 0.50   | yes      |
| `ip_obfuscation`               | 0.40   | yes      |
| `file_extension_tld`           | 0.40   | yes      |
| `open_redirect_param`          | 0.40   | yes      |
| `encoding_obfuscation`         | 0.35   | yes      |
| `brand_soundsquat`             | 0.30   | yes      |
| `punycode_malformed`           | 0.20   | yes      |
| `ascii_homoglyph`              | 0.20   | yes      |
| `risky_tld`                    | 0.15   | yes      |
| `brand_bitsquat`               | 0.15   | yes      |
| `excessive_subdomain_depth`    | 0.15   | yes      |
| `normalization_delta`          | 0.00   | info     |
| `confusable_char`              | 0.00   | info     |
| `confusable_in_path`           | 0.00   | info     |
| `idna_mapping_ambiguity`       | 0.00   | info     |
| `locale_case_ambiguity`        | 0.00   | info     |
| `parse_error`                  | 0.00   | meta     |

Each scoring detector lands at `severity ≥ medium` on its own, satisfying SC-1
for the canonical attack set; `risky_tld`, `punycode_malformed`, and
`ascii_homoglyph` are intentionally `low` alone (anomalous/contextual signals) so
they mainly matter in combination.

## Skipped detectors are a lower bound (FR-SCORE-3a)

If a scoring detector fails, it is added to `checksSkipped` as
`lexical:<detector_id>` and the score is a **lower bound**, not a complete
verdict. Fail-closed consumers should treat a result with skipped lexical
scoring detectors as untrusted rather than benign.
