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
| `terms` | Supported commercial modes, whether the licence requires attribution (a flag the caller acknowledges; see "Attribution is a caller assertion"), redistribution and caching posture. |
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

### Attribution is a caller assertion

`terms.attributionRequired` records that a source's licence requires
attribution. It is a flag, not a notice: the descriptor carries no attribution
text and no URL, so there is nothing for linklint to render.

`acceptAttribution: true` is the caller asserting that **they** will attribute
the source wherever they publish or display its results. The terms gate checks
that the assertion was made, and nothing reads it afterwards. linklint does not
render, display or otherwise satisfy attribution on the caller's behalf — and
cannot from its own front ends, because `@linklint/cli` and `@linklint/mcp` do
not depend on `@linklint/online`.

So the gate makes the obligation impossible to *miss*, not *satisfied*. A source
whose licence requires attribution cannot be constructed until the caller has
acknowledged the duty; discharging it stays with the caller. "Terms it cannot
honor" above is scoped the same way: for attribution, what is checked is the
caller's acknowledgement, not an attribution linklint produces.

The machine-readable provenance on each outcome and evidence record (for
example the source names `urlhaus.abuse.ch` and `phishtank`) is emitted whether
or not a source requires attribution. It identifies where a record came from; it
is not a licence-conformant attribution notice, and passing it through does not
by itself discharge the caller's duty.

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

### The live TLS source's subject is the input origin

`createTlsCertificateEnricher` reads `parsed.scheme` and `parsed.effectiveHost`
off the inspected input, so the origin it inspects is the one the caller passed.
An input that is not an absolute HTTPS URL with a host — an `http://` link, or a
hostless string — produces a `skipped` outcome carrying
`cause.code: "tls-not-https-endpoint"`, a `url` subject holding the raw input,
and no evidence. That guard sits ahead of the inspector call, so such an input
costs no DNS query and opens no socket. `tls-not-https-endpoint` is synthesized
by this enricher rather than by the framework — it is absent from
`TLS_OBSERVATION_CAUSE_CODES` and outside the framework list stamped by
`ENRICHMENT_SCHEMA_VERSION` — which is why it is documented here, with the
source that owns it.

**A successful redirect resolution does not imply TLS metadata for the resolved
endpoint.** A run over `http://iana.org/` that resolves to `https://www.iana.org/`
reports the chain hops as `success` and, in the same result, the TLS outcome as
`skipped` on the `http://` input. The certificate on the landing page was not
inspected, so nothing in `enrichment` describes it. The two outcomes are about
different endpoints, and a consumer must not read one as the other;
[`online-composition-root.md`](online-composition-root.md) § "Reading the
result" prints that run.

**The evidence gap this leaves is real and unclosed.** For an `http://` input,
the certificate a user would actually meet goes uninspected. `LINK-wwnrkjnm`
decided 2-0 to document these semantics rather than close the gap by declaring
the redirect chain a `dependsOn` prerequisite of the TLS source, for two reasons:

- **That wiring is a net evidence loss.** `runIsAvailable` admits a prerequisite
  only when every one of its outcomes is `success` or `no-hit`, so a single
  degraded chain outcome — an authorization refusal, a hop-limit stop, a
  redirect loop, a caller abort, an oversized body — suppresses the TLS source
  entirely. The `https://iana.org/` run published in
  [`online-composition-root.md`](online-composition-root.md), where the chain is
  `skipped` with `authorization-denied` beside a `success` TLS outcome, would
  invert to `prerequisite-unavailable`: HTTPS inputs that carry certificate
  evidence today would stop carrying it.
- **It would connect to an adversary-named host through a seam with no consent
  check.** A chain-discovered target is named by a `Location` header, which the
  threat model treats as attacker-chosen, and `SafeTlsInspector.inspect` takes
  `{ url, signal }` with no `authorize` callback — against register entry
  **F6**, which holds that construction is not consent to connect.

The successor shape is `LINK-boqmfrcn`, and a future proposal should take that
form rather than `dependsOn`: the redirect chain already completes an authorized
TLS handshake on every HTTPS hop it fetches, and `TransportConnection` carries
an optional `tls` field that `TransportEvidence` drops, so surfacing it adds no
connection and reopens no authorization question. No code path may hand a
redirect-discovered URL to `SafeTlsInspector.inspect`, and the shipped TLS
enricher passes it the input origin only. That rule is standing, not interim:
`LINK-sndjnmig` decided that no authorization seam will be added, because the
call is the consent and that consent covers only a URL the caller chose (see
[`safe-transport.md`](safe-transport.md) § "The call is the consent").

## The shared contract-test kit

`assertOnlineSourceContract(descriptor, options)` (test-only, not shipped) is the
reusable battery every adapter's suite calls. It proves the eight done-criteria
for any compliant source:

1. **opt-in** — a satisfied config preflights to `ok` with no I/O;
2. **missing credentials** — a required-credential source with no secret skips;
3. **secret handling** — a BYOK secret redacts through every serialization sink;
4. **freshness** — emitted freshness matches the declared capability;
5. **disclosure capture** — a consent-gated operation skips without consent;
6. **terms mode** — an unsupported mode or a declined attribution
   acknowledgement throws;
7. **failure-to-check** — every runtime refusal is a valid `EnrichmentCause`;
8. **graceful `checksSkipped`** — refusals map to skip states, never to safety.

A new adapter cannot ship a subtly non-conforming contract: its own tests fail
until the descriptor and behavior satisfy every criterion.
