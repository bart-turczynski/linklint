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

## Staged execution plans

The `enrichers` option is a caller-ordered `EnrichmentPlan`. Each enricher may
declare prerequisite check tokens through `dependsOn`:

```ts
import { inspectAsync, type Enricher, type EnrichmentPlan } from "linklint";

const redirectFixture: Enricher = {
  id: "redirect.fixture",
  layer: "resolution",
  async enrich(_result, context) {
    // Root stage: no earlier outcomes.
    console.assert(context.previousOutcomes.length === 0);
    return redirectReport;
  },
};

const destinationReputationFixture: Enricher = {
  id: "destination-reputation.fixture",
  layer: "reputation",
  dependsOn: ["resolution:redirect.fixture"],
  async enrich(_result, context) {
    const redirectOutcomes = context.previousOutcomes.filter(
      (outcome) => outcome.sourceId === "redirect.fixture",
    );
    return lookupFixtureDestinations(redirectOutcomes);
  },
};

const plan = [redirectFixture, destinationReputationFixture] satisfies EnrichmentPlan;
const result = await inspectAsync("https://example.com/start", { enrichers: plan });
```

The runner derives topological stages from these edges:

- Enrichers with no unresolved prerequisites run in parallel within the same
  stage. They receive the same frozen `previousOutcomes` array and cannot observe
  one another's in-flight output.
- A later stage receives every earlier outcome — including no-hit, skipped, and
  failure outcomes — in the caller's original plan order. Completion timing
  never changes final `enrichment.outcomes`, `checksRun`, or `checksSkipped`
  ordering.
- A prerequisite is available only when all of its outcomes are `success` or
  `no-hit`. Partial, skipped, or failed prerequisites prevent the dependent from
  running and produce `status: "skipped"` with
  `cause.code: "prerequisite-unavailable"` and the unavailable tokens in
  `cause.details.prerequisites`.
- Caller cancellation stays `caller-aborted` for both the active stage and work
  not yet started. It is not relabeled as a prerequisite failure.
- Every `<layer>:<id>` token must be unique. Unknown/duplicate prerequisites
  produce `invalid-plan`; actual dependency cycles produce `dependency-cycle`.
  These are explicit configuration skips, not provider failures or verdicts.

With no `dependsOn` declarations, all configured enrichers form the original K1
parallel stage. With no configured enrichers, `inspectAsync()` remains
byte-identical to `inspect()` and creates no enrichment report.

`cacheKey(result, context)` receives the same stage context, allowing dependent
sources to include a privacy-safe projection of prerequisite outcomes in their
key. Existing one-argument cache-key functions remain compatible. The framework
still never derives or stores a full-URL key automatically.

## Bounded execution and infrastructure isolation

Every configured enricher is hard-bounded by the runner, even when the caller
does not supply a governor. The default is exported as
`DEFAULT_ENRICHMENT_TIMEOUT_MS` and is currently 5000 ms. The effective policy,
in precedence order, is:

1. `Enricher.timeoutMs: null` explicitly disables the runner deadline for that
   source. Use this only when an outer runtime already enforces a hard bound.
2. A positive finite `Enricher.timeoutMs` overrides every default.
3. An admitted governor decision may supply a positive finite override or
   `null` as its explicit opt-out.
4. Otherwise the 5000 ms runner default applies. Zero, negative, `NaN`, and
   infinite values do not accidentally disable the bound.

The runner aborts the signal passed to the enricher when the deadline expires
and also races the promise itself, so a provider that ignores cancellation still
cannot stall the aggregate verdict. The abandoned promise remains observed;
rejecting after the timeout does not produce an unhandled rejection.

Rate limiting and backoff remain opt-in state policies supplied through
`EnrichmentGovernor`. The built-in governor identifies its refusal as
`rate-limited` or `backoff-active`; older custom governors that return only
`{ run: false }` remain compatible and produce `governor-denied`.

Every pluggable call is a total boundary. Exceptions from `enrich`, `cacheKey`,
cache `get`/`set`, or governor admission/lifecycle methods become attributed
failure outcomes and never reject `inspectAsync()`. Cache-key/read failures let
the provider run uncached; cache-write and governor lifecycle failures retain
valid provider evidence and add a failure outcome. Such partial sources appear
in both `checksRun` and `checksSkipped` and are unavailable as prerequisites,
which prevents a downstream stage from treating degraded infrastructure as a
wholly clean source. Thrown error messages are not copied into results.

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
- `prerequisite-unavailable`
- `invalid-plan`
- `dependency-cycle`
- `rate-limited`
- `backoff-active`
- `governor-denied`
- `governor-error`
- `timeout`
- `source-error`
- `invalid-output`
- `invalid-cached-output`
- `cache-key-error`
- `cache-read-error`
- `cache-write-error`

These are operational states, not malicious or benign verdicts.

## Subject-aware scoring and suppression

The `subject` on a structured outcome is also the subject of every finding in
that outcome. When projecting findings into top-level reasons, `inspectAsync()`
evaluates a host-scoped `suppressReasons` rule against that outcome subject's
registrable domain, not against the original input unconditionally.

For example, a rule scoped to `example.com` may suppress an original-host finding
whose outcome subject is `www.example.com`, but it does not suppress the same
reason code on a discovered `landing.example.org` outcome. Global rules (no
`host`) still apply to every subject. Invalid or hostless subjects never match a
host-scoped rule by guesswork. Legacy flat findings are wrapped with the original
inspection subject and retain their previous suppression behavior.

Outcome/evidence records remain source-attributed regardless of whether their
scoring projection is suppressed. Suppression annotates the top-level reason and
zeroes its weight; it never deletes evidence or turns a skipped/failure/no-hit
state into another status.

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
