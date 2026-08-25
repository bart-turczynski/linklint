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

`assertSourceTermsAccepted(descriptor, terms)` IS the construction gate: it
validates the descriptor and throws on a mode outside `terms.supportedModes` or a
missing acknowledgement when `terms.attributionRequired`. It takes no credential
and no consent, so it is safe to run while a source is being built — which is the
only place it runs.

`preflightOnlineSource(descriptor, config)` runs both seams — it calls
`assertSourceTermsAccepted` first, so there is one definition of the terms rule —
and returns either `{ ok: true, credential, disclosure }` (the credential to
reveal at the provider boundary and the cleared disclosure channels) or
`{ ok: false, cause }`.

### Where the construction gate runs

Every shipped reputation factory takes a **required** `terms` argument and calls
`assertSourceTermsAccepted` with its own descriptor before returning an enricher:
`createRdapAgeEnricher`, `createTlsCertificateEnricher`, `createDnsStateEnricher`,
`createUrlhausEnricher`, `createPhishTankEnricher`.

```ts
import { createUrlhausEnricher } from "@linklint/online/mirrors";

// Throws OnlineSourceConfigError('unsupported-commercial-mode'): abuse.ch grants
// free non-commercial / fair use, and commercial use needs a separate plan.
createUrlhausEnricher({
  terms: { commercialMode: "commercial", acceptAttribution: true },
  resolveIndex: () => snapshotIndex,
});
```

Only **URLhaus and PhishTank can actually refuse today**. RDAP, live TLS and DNS
declare all three commercial modes and require no attribution, so no legal
`terms` value makes their gate throw. That asymmetry is a property of those
**descriptors**, not of the gate, and it is why `terms` is required everywhere
rather than only on the two mirrors:

- an optional field would leave the unconditional claim above false for every
  call that omitted it;
- synthesizing a default posture for the omitted case would *be* the "silently
  downgraded to a weaker default" the same paragraph forbids — only the caller
  knows their commercial posture;
- a uniform required argument keeps the claim true if a descriptor later
  tightens. Narrowing RDAP's `supportedModes` would start refusing callers at
  construction with no factory change and no new argument to add.

The gate is **terms-only**. It never asks for a feed credential: the URLhaus
Auth-Key and the PhishTank app key are revealed only by the M4a/M5a *updaters*,
and querying a caller-owned local snapshot must not demand the key that
downloaded it. Credentials and disclosure stay on the runtime seam.

The three **resolution** enrichers (`createRedirectChainEnricher`,
`createDivergenceProbeEnricher`, `createEmbeddedWrapperEnricher`) deliberately
take no `terms`. M2 `terms` is feed licensing — `supportedModes`,
`attributionRequired`, `redistribution`, `caching` — and none of them consumes a
third-party feed; they fetch the inspected subject itself, or (for the wrapper
decoder) do no I/O at all. Authorization to contact a destination is a different
and explicitly runtime seam: the redirect chain and divergence probe already
enforce a stricter control, a mandatory per-hop `authorize` callback whose result
L0 re-checks for an exact URL match. Making construction a gate for them would
contradict the pinned guarantee that construction is never consent to connect.

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

Example evidence types: `rdap.domain` (RDAP, conjunctive), `urlhaus.match` and
`phishtank.match` (caller-owned mirrors, conjunctive), `tls.certificate`
(live TLS, **evidence-only**), `dns.records` (live DNS A/AAAA/NS/MX state,
**evidence-only**), and `dns.dnssec` (live DNSSEC validation state —
secure/insecure/bogus/indeterminate — **evidence-only**; an unsigned zone is not
risk and even a `bogus` verdict is only an anomaly). The live TLS source (M7) inspects the original
HTTPS hostname through the L0 observational transport and records the normalized
leaf certificate with its three independent validation axes (chain trust,
hostname match, validity window), DNS SANs, and certificate-policy OIDs including
DV/OV/EV posture. Certificate state is neutral on its own — DV alone is not risk —
so it emits `tls.certificate` evidence and never a scored finding; a connection or
validation problem is a `skipped`/`failure` outcome, never a safety claim.

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
