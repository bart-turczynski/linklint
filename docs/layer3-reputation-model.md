# Layer-3 reputation model (source-attributed scoring & provenance)

**Status:** shipped
**Issue:** `LINK-lbhcpjkj` (M10)
**Package:** `@linklint/online` (reputation + mirrors)

This is the durable description of the **Layer 3** reputation surface: the five
shipped source-attributed reputation sources, how their findings and evidence
relate to the deterministic score, the provenance every outcome carries, and the
deterministic acceptance gate that proves the model matches the output. It is the
Layer-3 analogue of the Layer-2 resolution acceptance gate
([`redirect-chain-resolution.md`](redirect-chain-resolution.md)).

It builds directly on two contracts and does not restate them:

- [`online-source-contract.md`](online-source-contract.md) (M2) — the per-source
  descriptor, terms/credential/disclosure gates, `OnlineSecret` BYOK wrapper, and
  the `evidence-only` vs `conjunctive-finding` scoring policy every source here
  declares and satisfies before it may reach the network.
- [`scoring.md`](scoring.md) — the generic probabilistic-OR aggregation, severity
  bands, weights, and the independent `confidence` measure. Layer 3 feeds that
  model; it does not define a second one.

## The five shipped sources

Every reputation source is a `layer: "reputation"` enricher composed into
`inspectAsync()` by the caller, publishing an `OnlineSourceDescriptor` and folding
its outcomes back through the same registry-driven reason path as lexical
findings. Two scoring classes exist, exactly as M2 defines them.

| Source | Package | Scoring class | Affirmative signal | Weight |
| --- | --- | --- | --- | --- |
| **RDAP** registration age | `@linklint/online/reputation` | `conjunctive-finding` | `young_domain_brand_risk` | 0.5 |
| **URLhaus** caller-owned mirror | `@linklint/online/mirrors` | `conjunctive-finding` | `malware_url_listed` | 1.0 |
| **PhishTank** caller-owned mirror | `@linklint/online/mirrors` | `conjunctive-finding` | `verified_phish_listed` | 1.0 |
| **TLS** live certificate | `@linklint/online/reputation` | `evidence-only` | `tls.certificate` evidence | 0 |
| **DNS/DNSSEC** record state | `@linklint/online/reputation` | `evidence-only` | `dns.records` + `dns.dnssec` evidence | 0 |

- **RDAP** (`rdap.registration-age`) queries the authoritative registry for the
  ICANN registrable domain and projects `young_domain_brand_risk` only when the
  registrable domain's RDAP age is below the young-domain threshold (default 90d)
  **AND** the domain already carries a lexical brand-impersonation signal
  (homoglyph / lookalike / skeleton / soundsquat / bitsquat / api-endpoint). Age
  alone is only evidence.
- **URLhaus** (`urlhaus.mirror`) queries a caller-owned local snapshot and projects
  `malware_url_listed` only on an **exact-URL** match to a currently-online record
  within a within-freshness snapshot. The match is never broadened to the host.
- **PhishTank** (`phishtank.mirror`) queries a caller-owned local snapshot and
  projects `verified_phish_listed` only on an **exact-URL** match to a
  human-verified, currently-online record within a within-freshness snapshot.
- **TLS** (`tls.live-endpoint`) observes the inspected origin's leaf certificate
  through the L0 safe pinned transport's observational capability, recording the
  three independent validation axes (chain trust, hostname match, validity window),
  DNS SANs, and certificate-policy OIDs incl. DV/OV/EV posture. Certificate state
  is neutral on its own — DV alone is not risk — so it emits `tls.certificate`
  evidence and **never** a scored finding.
- **DNS/DNSSEC** (`dns.state`) queries a recursive resolver for the host's
  A/AAAA and the registrable domain's NS/MX, and reports the zone's DNSSEC
  validation state. DNS state is neutral — a null MX, an NXDOMAIN answer, or an
  unsigned/`insecure` (even `bogus`) zone is neither safe nor malicious by that
  fact — so it emits `dns.records` + `dns.dnssec` evidence and **never** a scored
  finding.

## Scoring model

Reputation findings feed the same probabilistic-OR aggregation as every other
scoring reason (see [`scoring.md`](scoring.md)):

```
score = 1 − Π(1 − wᵢ)
```

over the **distinct** reason codes projected onto the result. Layer 3 adds no
second aggregator and no clamp; a reputation finding is projected exactly like a
lexical one, its weight attached from the reason-code registry
(`packages/core/src/schema/reason-codes.ts`), never supplied by the enricher.

- **Evidence-only sources carry weight 0.** TLS and DNS emit attributed evidence
  but **no finding**, so they never contribute a factor to the product and can
  never move the score or severity. Registering them alongside the conjunctive
  sources is byte-neutral on the verdict.
- **Non-over-scoring is a design property, not a runtime pass.** There is no dedup
  step. Each conjunctive source owns a **distinct** reason code
  (`young_domain_brand_risk`, `malware_url_listed`, `verified_phish_listed`), so no
  two sources project the same code and nothing is double-counted. In particular
  RDAP's `young_domain_brand_risk` is a *distinct* code from the lexical
  `brand_homoglyph` (and its siblings): the two compose **additively** as separate
  factors, and `young_domain_brand_risk` "never duplicates the lexical brand
  reason" it is conjoined with. The property is proven by the acceptance gate, not
  enforced by a dedup pass.
- **Confidence** follows the generic rule: the result's `confidence` is the minimum
  over the deterministic lexical base (`1.0`) and each successful finding's
  confidence. A skipped or failed source contributes nothing — its absence is
  already visible in `checksSkipped`.

## Provenance & attribution

Every outcome and every evidence artifact a Layer-3 source emits carries declared
provenance and honest no-match semantics:

- **Declared provenance** — `provenance.kind === "declared"` naming the producing
  source (name + version). Core rejects any reputation outcome or evidence whose
  provenance is not `declared` (`inspect-async.ts` `normalizeOutput`), so an
  unattributed reputation claim can never reach the result.
- **Subject** — every outcome and evidence artifact is tied to the inspected
  host/URL it describes (`EnrichmentSubject`), so an exemption for the original
  host cannot suppress evidence about a discovered destination, and the score path
  evaluates each finding against its own outcome subject.
- **`observedAt`** — a point-in-time instant for the observation.
- **Freshness** — descriptor-declared: the caller-owned mirrors declare expiry and
  go **stale** past a cadence-derived `expiresAt` (a stale snapshot demotes a match
  to evidence-only); the live observers (RDAP by TTL, TLS and DNS as point-in-time
  snapshots) declare freshness per their descriptor, with TLS/DNS staying
  `unknown`.
- **`absence-is-not-safety`** — the literal `noMatchSemantics` pin every source
  declares. An honest no-hit (a clean sibling path, a 404 registry answer, an empty
  snapshot, a NODATA resolver answer) is a `no-hit`/`success` with no finding — it
  is **never** a safety claim. A DNS/TLS/provider/quota/parser problem degrades to
  a structured `skipped`/`failure` cause, never to benign.

## Determinism / acceptance

The model is verified by a deterministic, **zero-live-network** gate — the
Layer-3 analogue of the Layer-2 resolution acceptance gate. All fixtures are
canned; the clock is fixed; nothing in CI needs a live credential, provider
account, or network. Three units compose the gate:

- **Cross-source descriptor contract fan-in** —
  `packages/online/test/contract/reputation-sources-contract.test.ts` enumerates
  all five real descriptors in one table and drives each through the shared
  8-criteria M2 contract kit. A sixth reputation source shipped without an entry is
  a *visible* omission in this gate rather than a silent one.
- **Per-source acceptance corpus** —
  `packages/online/test/reputation-acceptance.test.ts` over
  `packages/online/test/corpus/reputation-corpus.ts` drives the five **real**
  enrichers through `inspectAsync` on a labeled positive/negative corpus. Each row
  targets one source with a real fixture while the other four are composed from
  inert ports, asserting per-row attribution (declared provenance, `observedAt`,
  declared freshness), the exact expected finding codes, correctly-attributed
  evidence, and — critically — that **no other composed source over-contributes**.
  It holds `1.0` precision and recall.
- **Cross-source composition properties** —
  `packages/online/test/reputation-composition.test.ts` drives several sources
  live at once and proves the multi-active interactions the corpus defers: that
  RDAP + URLhaus + PhishTank firing together each emit their finding **exactly
  once** with no reason code double-counted (the composed score equals the
  probabilistic-OR of the distinct reason weights); that evidence-only TLS + DNS
  are byte-neutral on the score; that one source degrading (an RDAP fault) does not
  corrupt the other four; and that composed disclosure never exceeds any single
  source's descriptor and never leaks a BYOK mirror secret.

Together these prove the shipped Layer-3 reputation model matches its output: the
five sources compose additively, attribute honestly, and do not over-score.
