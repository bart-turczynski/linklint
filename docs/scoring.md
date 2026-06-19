# Scoring

> Version-pinned (`dataVersions.weights`). Source of truth:
> `packages/core/src/schema/reason-codes.ts` (weights) and
> `packages/core/src/scoring/` (aggregation + bands). Current weights version:
> **1.0**.

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

Worked example (PRD §5.3): `userinfo_present` (0.5) + `mixed_script` (0.4):

```
score = 1 − (1 − 0.5)(1 − 0.4) = 1 − 0.5 × 0.6 = 0.7 → high
```

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

## Weights table (v1, hand-tuned — OQ-3)

Weights are hand-tuned and transparent (not learned), so the verdict stays
explainable. Reliability is encoded in the weight itself — there is no separate
`confidence` field in v1 (FR-SCORE-2b).

| Reason code                    | Weight | Scoring? |
| ------------------------------ | ------ | -------- |
| `dangerous_scheme`             | 0.90   | yes      |
| `bidi_override`                | 0.60   | yes      |
| `invisible_char`               | 0.50   | yes      |
| `userinfo_present`             | 0.50   | yes      |
| `embedded_domain_in_subdomain` | 0.50   | yes      |
| `mixed_script`                 | 0.40   | yes      |
| `ip_obfuscation`               | 0.40   | yes      |
| `encoding_obfuscation`         | 0.35   | yes      |
| `punycode_malformed`           | 0.20   | yes      |
| `risky_tld`                    | 0.15   | yes      |
| `normalization_delta`          | 0.00   | info     |
| `confusable_char`              | 0.00   | info     |
| `confusable_in_path`           | 0.00   | info     |
| `parse_error`                  | 0.00   | meta     |

Each scoring detector lands at `severity ≥ medium` on its own, satisfying SC-1
for the canonical attack set; `risky_tld` and `punycode_malformed` are
intentionally `low` alone (anomalous/contextual signals) so they mainly matter in
combination.

## Skipped detectors are a lower bound (FR-SCORE-3a)

If a scoring detector fails, it is added to `checksSkipped` as
`lexical:<detector_id>` and the score is a **lower bound**, not a complete
verdict. Fail-closed consumers should treat a result with skipped lexical
scoring detectors as untrusted rather than benign.
