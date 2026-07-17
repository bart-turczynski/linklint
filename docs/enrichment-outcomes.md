# Structured enrichment outcomes

Schema 1.3 adds an optional, versioned `enrichment` report to results produced by
`inspectAsync()` with configured enrichers. The report keeps source evidence and
operational coverage separate from `reasons`, which remain the scoring projection.

The synchronous `inspect()` path is still deterministic and zero-network. It never
adds `enrichment`. `inspectAsync()` with no enrichers remains byte-identical to
`inspect()`.

## Versions

- `InspectResult.schemaVersion` is `1.3`.
- `InspectResult.enrichment.schemaVersion` is independently versioned and is
  currently `1.0` (`ENRICHMENT_SCHEMA_VERSION`).
- The `enrichment` field is present only when at least one enricher is configured.

Independent versioning lets evidence consumers pin the online contract without
coupling every evidence evolution to lexical detector data versions.

## Source report

New enrichers return an `EnrichmentReport`:

```ts
import {
  ENRICHMENT_SCHEMA_VERSION,
  type Enricher,
  type EnrichmentReport,
} from "linklint";

const dnsFixture: Enricher = {
  id: "dns.fixture",
  layer: "resolution",
  async enrich(): Promise<EnrichmentReport> {
    return {
      schemaVersion: ENRICHMENT_SCHEMA_VERSION,
      outcomes: [
        {
          sourceId: "dns.fixture",
          layer: "resolution",
          status: "success",
          subject: { kind: "host", value: "example.com" },
          observedAt: "2026-07-17T08:30:00.000Z",
          provenance: {
            kind: "declared",
            source: { name: "dns.fixture", version: "1.0.0" },
            data: { name: "dns-fixtures", version: "2026-07-17" },
          },
          freshness: {
            status: "fresh",
            expiresAt: "2026-07-17T08:35:00.000Z",
          },
          evidence: [
            {
              type: "dns.answer",
              subject: { kind: "host", value: "example.com" },
              observedAt: "2026-07-17T08:30:00.000Z",
              provenance: {
                kind: "declared",
                source: { name: "dns.fixture", version: "1.0.0" },
                data: { name: "dns-fixtures", version: "2026-07-17" },
              },
              freshness: {
                status: "fresh",
                expiresAt: "2026-07-17T08:35:00.000Z",
              },
              payload: { addresses: ["192.0.2.1"], ttlSeconds: 300 },
            },
          ],
          findings: [],
        },
      ],
    };
  },
};
```

One source may return multiple outcomes, for example one per authorized redirect
hop. Every outcome and evidence artifact carries its own subject, observation
time, provenance, and freshness so serialization does not lose attribution.
Evidence payloads are extensible JSON-safe objects; non-finite numbers, functions,
cycles, and class instances are rejected at the runner boundary.

## Status semantics

| Status | Meaning | Coverage token |
| --- | --- | --- |
| `success` | The source completed and returned affirmative evidence and/or scored findings. | `checksRun` |
| `no-hit` | The source completed but found no affirmative match. This is not a safety claim. | `checksRun` |
| `skipped` | Authorization, policy, cancellation, or capacity prevented completion. | `checksSkipped` |
| `failure` | An attempted source operation failed or returned an invalid contract. | `checksSkipped` |

Skipped and failed outcomes carry a machine-readable `cause.code`. A source with
multiple subject outcomes may appear in both `checksRun` and `checksSkipped` when
it completed only part of its work. `findings` are allowed only on `success` and
are projected into the existing `reasons`, score, severity, confidence, and
confusables fields. Evidence never replaces the offline lexical result.

Core-generated degradation codes currently include:

- `caller-aborted`
- `governor-denied`
- `timeout`
- `source-error`
- `invalid-output`
- `invalid-cached-output`

These are operational states, not malicious or benign verdicts.

## Validation and identity

`inspectAsync()` validates each structured report before merging it:

- the report version must be supported;
- every `sourceId` and `layer` must exactly match the producing enricher;
- stable source/evidence identifiers must be non-empty, while subject values
  preserve the inspected URL/host string exactly;
- `observedAt` and non-null `expiresAt` values must be parseable ISO-8601
  instants;
- structured source and evidence provenance must be declared;
- findings must use registered reason codes and valid confidence values; and
- payloads and cause details must be JSON-safe.

Malformed or mismatched output becomes a `failure` outcome with
`cause.code: "invalid-output"`; it contributes no reasons. Consumers can use the
exported `isEnrichmentReport(value, expectedIdentity?)` guard when accepting or
deserializing reports outside the runner.

## Legacy findings migration

The pre-K6 `Promise<EnricherFinding[]>` return remains accepted during the
compatibility window. Core wraps it in a successful structured outcome with:

```ts
provenance: {
  kind: "legacy-incomplete",
  source: null,
  data: null,
}
```

Core does not invent provider or dataset provenance. An empty legacy array is
recorded as a successful but semantically unknown legacy result, not upgraded to
`no-hit`; only a structured source can assert no-match semantics. Existing legacy
findings continue to score exactly as before.

New adapters should return only `EnrichmentReport`. The flat shape will be
narrowed or removed only through a separate public-contract release with updated
migration notes and contract tests.

## Caching

The enrichment cache stores the complete `EnricherOutput`, not only its scored
findings. Structured cache hits therefore preserve original observation times,
provenance, freshness, evidence payloads, and no-hit semantics. Only reports whose
outcomes are all `success` or `no-hit` are cached; skipped, failed, and partial
reports are not negative-cached.
