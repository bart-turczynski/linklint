# Online-source contract (Epic M blocking contract)

**Status:** shipped
**Issue:** `LINK-nlnyqofz` (M2)
**Package:** `@linklint/online` (root export)

This is the blocking contract every Epic M provider adapter — RDAP registration
age (M1), caller-owned URLhaus (M4) and PhishTank (M5) mirrors, live TLS (M7),
and DNS/DNSSEC (M9a) — must declare and satisfy **before** it may reach the
network or disclose an inspected subject. It turns the prose policy in
[`online-runtime-boundary.md`](online-runtime-boundary.md) ("Licensing, privacy,
and commercial modes" and "Configuration, credentials, and storage") into a
typed, validated, contract-tested surface.

It replaces the earlier idea of a single universal k-anonymity abstraction:
there is no package-wide privacy or provider-compatibility claim. Each source
publishes its own machine-readable posture instead.

## What core already owns

The core `linklint` package owns the **evidence schema** — `EnrichmentReport`,
`EnrichmentOutcome`, `EnrichmentProvenance`, `EnrichmentFreshness`,
`EnrichmentSubject`, and the `success` / `no-hit` / `skipped` / `failure` status
model (see [`enrichment-outcomes.md`](enrichment-outcomes.md)). M2 does **not**
redefine any of that. M2 is the discipline layer above it: the per-source
metadata and gates that decide whether an adapter may run at all, and that keep
its emitted outcomes honest.

## The descriptor

Every source publishes an inert `OnlineSourceDescriptor`:

| Field | Meaning |
| --- | --- |
| `id`, `displayName`, `version`, `layer` | Identity; `id` matches the producing enricher. |
| `evidenceScope` | The evidence `type` tokens the source may emit. |
| `disclosure` | Recipient, the channels that leave the machine (`sends`), and which are consent-gated (`consentRequired`). |
| `credentials` | `none`, or a `required` / `optional` BYOK slot with `scheme` and `label`. |
| `terms` | Supported commercial modes, attribution duty, redistribution and caching posture. |
| `dataOrigin` | `live-provider` (with recipient) or `caller-owned-mirror` (`bundled: false`, always). |
| `freshness` | Whether the source can declare expiry and whether it goes stale. |
| `scoring` | `evidence-only` or `conjunctive-finding` (see below). |
| `noMatchSemantics` | The literal pin `"absence-is-not-safety"`. |

`assertValidSourceDescriptor` rejects a malformed or internally inconsistent
descriptor — for example a consent-gated channel that is sent but not gated, a
`none` disclosure mixed with another channel, or a mirror that claims to be
bundled.

## Two enforcement seams

The contract distinguishes two failure kinds, and enforces them differently:

- **Terms are a construction gate.** Requesting a commercial mode a source does
  not support, or declining required attribution, throws
  `OnlineSourceConfigError`. A source is never constructed under terms it cannot
  honor, and never silently downgraded to a weaker default. Adapters whose terms
  cannot support the selected mode stay parked rather than shipping degraded.
- **Credentials and disclosure are runtime gates.** A missing required
  credential or an un-granted consent-gated channel produces a structured
  `EnrichmentCause`, so the operation degrades to `skipped` /`checksSkipped` with
  a machine-readable reason (`credentials-missing`,
  `disclosure-consent-required`). It never falls back to an anonymous call and
  never fabricates a safety claim.

`preflightOnlineSource(descriptor, config)` runs both seams and returns either
`{ ok: true, credential, disclosure }` — the credential to reveal at the provider
boundary and the cleared disclosure channels — or `{ ok: false, cause }`.

## BYOK secrets

Caller credentials are wrapped in `OnlineSecret` (`createOnlineSecret`). The only
reader is `.reveal()`, called at the moment a value enters a provider
authorization header and nowhere else. Every incidental serialization path —
`String()`, template interpolation, `JSON.stringify`, `util.inspect` /
`console.log` — yields the fixed `REDACTED_SECRET` placeholder. The value is held
in a closure, not an own property, so it is unreachable through enumeration,
structured clone, cache keys, or evidence payloads.

## Evidence and the deterministic score

Online evidence is **additive**; it never replaces the deterministic lexical
verdict. The `scoring` field resolves how non-reproducible online observations
relate to the score:

- `evidence-only` sources contribute attributed, informational evidence and
  **never** scored findings — the L3/L4/L5 precedent (weight-0 informational
  codes).
- `conjunctive-finding` sources may contribute findings, but only from
  affirmative, subject-tied, within-freshness evidence. A no-match or a
  freshness-degraded observation stays evidence-only. Absence is never safety.

## The shared contract-test kit

`assertOnlineSourceContract(descriptor, options)` (test-only, not shipped) is the
reusable battery every adapter's suite calls. It proves the eight done-criteria
for any compliant source:

1. **opt-in** — a satisfied config preflights to `ok` with no I/O;
2. **missing credentials** — a required-credential source with no secret skips;
3. **secret handling** — a BYOK secret redacts through every serialization sink;
4. **freshness** — emitted freshness matches the declared capability;
5. **disclosure capture** — a consent-gated operation skips without consent;
6. **terms mode** — an unsupported mode or declined attribution throws;
7. **failure-to-check** — every runtime refusal is a valid `EnrichmentCause`;
8. **graceful `checksSkipped`** — refusals map to skip states, never to safety.

A new adapter cannot ship a subtly non-conforming contract: its own tests fail
until the descriptor and behavior satisfy every criterion.
