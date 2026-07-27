# linklint architecture

## 1. Intent

linklint is an offline-first URL inspection engine: synchronous, deterministic, zero-network, never throws. Every verdict is explainable — each `InspectResult` carries named reason codes with weights and human-readable `detail` strings.

The core architectural rule: **channels do not implement detectors.** `packages/core` owns everything that affects a verdict; `packages/mcp` and `packages/cli` are thin adapters that call `inspect()` and present or enforce the result.

### 1.1 Scope of claim — the structural claim and the name-never-create rule (canonical)

This is the canonical statement of what linklint asserts. Everything downstream
— the README's "What linklint does not do", `SECURITY.md`'s scope section, the
`KNOWN_AND_ACCEPTED` list in `test/corpus/embarrassment.ts`, and the decision
records below (notably §6.1.1 and §6.1.2) — restates or applies this section
and must not contradict it. If they diverge, this section wins.

**The claim.** linklint commits to exactly one:

> **(a) STRUCTURAL.** The string is not what it presents itself to be.

It explicitly **rejects** the other:

> **(b) SEMANTIC.** "We detect impersonation of high-value brands."

Claim (a) is settleable from the string alone, offline, deterministically, and
for all time — it names a property of the input, not a property of the world.
Claim (b) requires knowing which words are brands, which brands are worth
impersonating, and what the site at the other end does. linklint has none of
that and does not pretend to.

**The three settled forms of claim (a).** These are one claim in three shapes,
not three claims. Each is a demonstrable property of the string:

1. **Normalization delta** — `normalize(input) !== input`. The string reads one
   way and resolves another, so something is hiding. This is the original and
   most common form: `separator_lookalike`, `invisible_char`, `brand_homoglyph`.
2. **Reader disagreement** — `read_A(input) !== read_B(input)`. Two conforming
   readers resolve the same string to different destinations, so at most one of
   them reaches where the reader thinks it does. `ambiguous_authority` (0.65,
   "parsers disagree on the host"), `ambiguous_numeric_host` (0.3, "a browser
   rejects it, non-browser clients may resolve it"), `idna_mapping_ambiguity`
   and `locale_case_ambiguity`. §6 states the same rule from the other end:
   **"the discriminator is *disagreement between standards*, not exotic input."**
3. **False self-description** — the string declares its own type and the
   declaration does not hold. `xn--` announces "I am an ACE-encoded IDN"; when it
   does not decode, `punycode_malformed` fires at 0.2.

Form 2 and form 3 are why linklint **does** make protocol-validity claims, and
saying otherwise contradicts the shipped registry. What makes them claim (a) is
not that the string is invalid — it is that the invalidity is a false claim the
string makes about itself, or a fork in how the string will be read.

**What this excludes: well-formed but unusable.** A string that every reader
agrees on, that makes no false claim about itself, and that merely fails, is
**not** a claim-(a) finding. The worked case is host length: a 64-character DNS
label is syntactically a hostname, is read identically by every parser, and is
simply too long to resolve. Nothing is hidden and nobody disagrees. It is pinned
benign in `test/corpus/vectors.ts` and an implementation of DNS length caps was
written and reverted on exactly this reasoning (`LINK-ygglwkuy`,
`LINK-tukbqyjg`). "Malformed" and "deceptive" are not the same claim, and only
the second is chartered.

**Two boundaries this section does NOT yet settle** — do not read an answer into
the silence:

- **Context-dependent names.** `svc.internal`, `home.arpa` and the rest of the
  RFC 6761 set make no false claim and provoke no disagreement; the same string
  simply names different machines on different networks. That is "not the same
  thing everywhere", which is a different property from "not itself", and
  whether it is in scope is open (`LINK-mgnbgicq`).
- **Where `parse_error` / `invalid` sit.** The fail-closed doctrine is a validity
  claim of a sort, so it needs an articulated relationship to the three forms
  above. The working distinction — input linklint *cannot analyze*, versus input
  that is analyzable but non-conforming — is plausible and currently unwritten.

**The rule.** The brand watchlist (`data/brands.ts`) may only be consulted to
**NAME** a structural anomaly that was already detected independently. It may
**never CREATE** a finding. A detector whose firing condition depends on a
watchlist hit is claim (b) wearing claim (a)'s clothes; a detector that fires on
a structural precondition and then reads the list to say *what* the string folds
onto is claim (a).

This is the test — not list size, not tuning — that authorized deleting
`brand_lookalike`, `brand_soundsquat`, and `brand_bitsquat` (`LINK-cphogucn`,
schema `1.4` / weights `1.13`) while keeping `brand_homoglyph`,
`homograph_skeleton_collision`, `brand_idna_collapse`, and
`brand_locale_collapse`. The deleted three satisfied **none of the three forms**
— `normalize(input) === input`, no reader disagreed, and the string described
itself accurately; the only thing wrong with `paypai.com` is that a human might
misread it, which is claim (b). The survivors each carry a structural
precondition — a demonstrated fold, a demonstrated UTS#39 confusable, a
demonstrated disagreement between two standards' readings of the same host —
that is satisfied *before* the list is read. See §6.1.2 for the per-code record.

**The stated limitation.** linklint does not catch `paypal-login.com` or
`apple-id-verify.com`. Every label in both is a real, correctly spelled word in
a normal arrangement; nothing about either string is malformed, disguised, or
inconsistent. They score `0.00`/`info` and **that is the correct answer for what
linklint claims**. They read as suggestive only to a reader who already knows
PayPal and Apple are brands worth impersonating — which is claim (b).

**This is a scope boundary, not a bug and not a backlog item.** No issue should
be opened to "fix" it, and if either string ever starts scoring, that is a false
positive to investigate rather than a win. The distinction is visible in code:
`test/corpus/embarrassment.ts` carries genuine misses in
`EMBARRASSMENT_CORPUS` (asserted red until fixed) and these two in
`KNOWN_AND_ACCEPTED` (deliberately unasserted). The neighbouring case shows the
line is structural and not a matter of degree: since `LINK-lippdgpn`,
`paypa1-login.com` scores `0.50`/`medium` because `paypa1` contains a digit that
folds to a letter, while `paypal-login.com` — the same shape, same pretext
token, no fold — stays at `0.00`.

**That limitation has a name and a measured shape** (`LINK-pralkaeo`).
`paypal-login.com` is not an arbitrary example: it is a textbook **combosquat** —
a correctly spelled brand token joined to an additive word, with no typo and no
homoglyph anywhere in the string. Kintis et al. (CCS 2017) measured the class
across six years of DNS data and found it **~100× more prevalent than
typosquatting** and, decisively, **largely benign** — the bulk of it is defensive
registration, partner and reseller sites, fan pages, and regional variants owned
by the brand itself.

That pairing is why combosquatting is a **stated non-goal and not a gap**. It is
invisible to every mechanism linklint has, by construction: there is no
misspelling for edit distance to measure, no confusable for the UTS#39 skeleton
to collapse, and `normalize(input) === input` so nothing folds. Detecting it
would require deciding that `paypal` is a brand worth protecting *and* that
`-login` is hostile where `-community` or `-developer` are not — claim (b) in
both halves. The base rate then makes it worse than merely out of scope: a
detector for this class is wrong most of the time it fires, on a class two orders
of magnitude larger than the one linklint does catch.

This is recorded history rather than a prediction. `brand_combosquat` shipped as
G3 (`LINK-phghrnqc`), was investigated (`LINK-cqdrdvfu`), and was deleted
outright with `brand_in_path` (`LINK-blgvypxk`) on exactly this reasoning; §6.1.2
applied the same rule to the three edit-distance detectors. Like the boundary
above, it should not be re-filed, and a proposal to restore the class has to
argue with Kintis' base rate first.

**The list's role.** The watchlist is **not a coverage mechanism and never will
be.** It is a bounded precision instrument that upgrades "this string is
structurally odd" to "this string is impersonating PayPal". Its charter is
therefore bounded, it is hard-capped, and additions are gated on measured
fold-reachability rather than on brand prominence (`LINK-stnruoge`). Growing it
buys sharper explanations of anomalies already found — never new findings.

**Why the literature ratifies this rather than merely permitting it.**

- **Liu et al., PhishIntention (USENIX Sec 2022)** — false alerts fell **86.5%**
  (1,033 → 139) at comparable recall, and the entire reduction came from adding
  a credential-taking check on top of brand resemblance. A URL-string detector
  has the resemblance half and none of the intent half, so it must not emit a
  phishing verdict from brand-lookalike strings.
- **Szurdi et al. (USENIX Sec 2014)** — "about half of the possible typo domains
  identified by lexical analysis are truly typo domains." **~50% is the ceiling
  for pure lexical squatting detection**, before malice is even asked about.
- **Tian et al. (IMC 2018)** — 657,663 lexical squatting candidates yielded
  **1,175 verified phishing domains (≈0.18%)**. The base rate of a claim-(b)
  string detector is catastrophic.
- **DynaPhish (USENIX Sec 2023)** — any fixed reference list is **inherently
  incomplete**. This is why the watchlist's hard cap is a correct posture and
  **not a defect**: an uncapped list would still be incomplete, while trading
  away the precision that is the list's only justification.

**A clean result is not a safety claim** (`LINK-vwjtdtzn`). The fail-closed
doctrine has always covered `invalid` — `score: null`, contract-tested, never a
fallback to a second parser — and the clean case needs the same discipline for a
stronger reason: it is the one that gets read as an endorsement. Turn the two
measurements above around. Szurdi puts the ceiling for pure lexical squatting
detection at **~50%**, and Tian finds that only **0.18%** of lexical candidates
are verified malicious. The first number says a structural detector misses about
half of what it is *chartered* to catch; the second says the chartered category
barely overlaps with malice in the first place. Together: **the absence of a
structural flag carries essentially no information about safety.**

So `0.00`/`info` means exactly one thing — *no structural anomaly was found in
this string* — and it must never be rendered, described, or field-named as
"safe", "clean", "OK", or "passed". This is not a caveat to attach where
convenient; it is a property of every surface that shows a result, and the CLI,
the MCP tool description, and the README each carry it. The L3 enrichment layer
already states the same rule for its own quiet outcome — "a no-match is not a
safety claim" ([`enrichment-outcomes.md`](enrichment-outcomes.md)) — and this is
that rule for L1.

The consumer-side consequence: a fail-closed integration must not treat a low
score as clearance. It composes linklint with other signals, or it treats
"unknown" as its default and lets linklint move a URL only in the *deny*
direction. `enforcement/` ships both wrappers this way — they deny on a
deceptive verdict and on invalid input, and a clean verdict merely fails to
trigger a denial rather than granting one.

**Offline-first is a correctness property, not only a privacy one**
(`LINK-riupozbo`). The zero-network core is described everywhere else in this
repo as a privacy, determinism, and latency property — no telemetry, nothing
leaving the machine, the same answer for the same string for all time. Those are
true, and they are the weaker half of the argument. The stronger half: **a
detector that never fetches cannot be served a decoy.**

Cloaking is the standard evasion against anything that does fetch. CrawlPhish
(Zhang et al., S&P 2021) documents **eight distinct client-side evasion types**
in deployed phishing kits — fingerprint the visitor, serve benign content to
anything that looks like a crawler, serve the attack to everyone else. PhishFarm
(Oest et al., S&P 2019) measured what that is worth: trivial cloaking cut
blocklisting by **more than 55%**. Every fetch-based detector is exposed to this
by construction, because the attacker controls the response and can tell the
detector and the victim apart.

linklint's input is the string the victim was actually handed. There is no
response for an attacker to vary, no visitor to fingerprint, and no
crawler-versus-victim divergence to exploit. This is **structural immunity, not
resistance** — not that cloaking linklint is hard, but that cloaking has no
surface to act on. It buys nothing against claim (b): a detector that never
fetches still cannot know what a site does, which is the same limit stated
throughout this section. Within claim (a), though, what linklint reads is
exactly what the victim was given.

**Where a denylist legitimately sits** (`LINK-riupozbo`). linklint is regularly —
and fairly — asked why the watchlist is not an allowlist. The answer is not that
denylists are underrated. It is that MITRE already positions them exactly where
linklint sits. CWE-20 (*Improper Input Validation*), verbatim:

> Do not rely exclusively on looking for malicious or malformed inputs. This is
> likely to miss at least one undesirable input [...] However, denylists can be
> useful for detecting potential attacks or determining which inputs are so
> malformed that they should be rejected outright.

Both halves are load-bearing, and quoting only the second would be the same
overclaim this section exists to prevent. The first half is why linklint is not
a gate, and it is the consumer-side consequence above restated by the authority
everyone cites when they say denylists do not work. The second half is the
charter: a **supplementary detection layer**, composing with an allowlist rather
than substituting for one. The two answer different questions — an allowlist
answers *may I go here*, which is a policy the caller owns and which §8 exposes;
linklint answers *is this string what it presents itself to be*, which no
allowlist can settle, because a string that folds onto an allowed host is
precisely the case an allowlist gets wrong.

## 2. Repository layout

```
linklint/
  packages/
    core/           # linklint npm package — inspect(), 36 checks, scoring, policy, schema
    mcp/            # @linklint/mcp — local-only MCP server (check_url / check_domain)
    cli/            # @linklint/cli — offline CLI (linklint check / batch)
    online/         # @linklint/online — Node/server safe transport + deterministic fixtures
  docs/
    architecture.md
    online-runtime-boundary.md # Accepted ownership/packaging decision for online work
    safe-transport.md # L0 authorization, pinning, budget, and outcome contract
    redirect-chain-resolution.md # L1 redirect/refresh authorization and evidence
    reason-codes.md # Full reason-code registry with detection logic and examples
    scoring.md      # Scoring model, severity bands, weights table (v1.3)
    locale-case-mapping.md # Locale-tailored case mapping audit (the Turkish-I class)
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

5. **Detector execution** — run 36 independent lexical checks: 4 structural scans ahead of parsing, then 32 parsed-context detectors. The 5 agent-gated parsed detectors run only under `agentMode`. A detector failure adds `lexical:<id>` to `checksSkipped` rather than aborting the inspection. Any skipped scoring detector means the score is a lower bound, not a complete verdict.

6. **Policy layer** (optional) — apply caller-configured allow/deny rules. Policy reasons carry `weight: 0` and never change `score` or `severity`.

7. **Scoring** — aggregate scoring reasons with probabilistic-OR: `score = 1 − ∏(1 − wᵢ)`. Weights are version-pinned.

8. **Serialization** — return the stable `InspectResult` schema with `checksRun`, `checksSkipped`, `schemaVersion`, and `dataVersions`.

## 5. Detectors

`packages/core/src/detectors/` contains 36 lexical checks: 4 structural scans and 32 parsed-context detectors. Parsed detectors implement:

```ts
interface Detector {
  id: string;
  layer: 'lexical' | 'resolution' | 'reputation';
  run(context: InspectionContext): DetectorFinding[];
}
```

Detectors emit findings only — they never read weights. The core attaches weights from the version-pinned table (`packages/core/src/scoring/weights.ts`) keyed by reason code.

The 36 checks group into seven families (listed by **check id**; a single check
may emit several reason codes):

| Family | Detectors |
|--------|-----------|
| **Authority spoofing** | `userinfo_present`, `embedded_domain_in_subdomain`, `ambiguous_authority`, `ip_obfuscation`, `ip_classification`, `ambiguous_numeric_host`, `separator_lookalike`, `excessive_subdomain_depth` |
| **Homographs & confusables** | `mixed_script`, `confusable_char`, `ascii_homoglyph`, `punycode_malformed`, `normalization_delta`, `idna_mapping_ambiguity`, `locale_case_collapse`, `homograph_latin_skeleton`, `idn_host` |
| **Brand impersonation** | `brand_lookalike`, `homograph_skeleton_collision` |
| **Dangerous payloads** | `dangerous_scheme`, `file_extension_tld`, `suspicious_extension`, `open_redirect_param` |
| **Hidden characters** | `invisible_char`, `bidi_override`, `control_char`, `encoding_obfuscation`, `percent_encoding_malformed`, `confusable_in_path` |
| **Contextual signals** | `risky_tld`, `bait_tokens` |
| **Agent-gated** | `prompt_injection_url`, `api_endpoint_impersonation`, `credential_harvesting`, `data_exfiltration`, `ssrf_cloud_metadata` |

Informational detectors (`confusable_char`, `confusable_in_path`, `normalization_delta`, `idna_mapping_ambiguity`, `locale_case_ambiguity`) have weight 0 — they annotate without raising severity. `idna_mapping_ambiguity` and `locale_case_ambiguity` each escalate to a weight-0.5 scoring code (`brand_idna_collapse`, `brand_locale_collapse`) when the alternate reading lands on a watchlist brand exactly.

## 6. Result schema

Every channel returns the same `InspectResult` (schema version `1.5`):

```ts
interface InspectResult {
  schemaVersion: '1.5';
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
  pslSnapshot: PslSnapshot;        // { date, stale } — provenance + advisory staleness of the PSL trust boundary (schema 1.2)
  enrichment?: EnrichmentReport;  // inspectAsync with configured work; versioned outcomes/evidence (schema 1.3)
}
```

Key invariants:

- `status: "invalid"` → `score: null`, `severity: null`, `parse_error` reason, `checksRun: []`. Invalid input is **not** benign.
- `score: 0` → `severity: "info"`. A parsed URL with zero scoring weight is benign even when informational reasons are present.
- `dataVersions` is present on both valid and invalid results for reproducibility.
- `pslSnapshot` (schema 1.2) is present on both valid and invalid results. `date` is the deterministic provenance date of the bundled PSL snapshot (the pinned `tldts` release date, a tight upper bound on the true list date); `stale` is an **advisory, time-relative** flag — the one field on the result that reflects wall-clock time — computed against a 180-day freshness window and `null` when the date is unknown. See §6.1.
- `enrichment` (schema 1.3) is present only when `inspectAsync()` receives configured enrichers. It contains independently versioned source outcomes/evidence and is absent from synchronous and empty-plan output.
- A non-empty `confusables[]` requires a corresponding `confusable_char` or `confusable_in_path` reason, and vice versa.
- If a lexical scoring detector fails, its ID appears in `checksSkipped` as `lexical:<id>`. The layer stays in `checksRun`; the score is a lower bound. Fail-closed consumers should treat results with `lexical:*` in `checksSkipped` as untrusted rather than benign.
- `confidence` is `1.0` for every deterministic lexical result (sync `inspect()`, including `status: "invalid"`). It is **independent** of `score`/`weight` and never feeds score aggregation; `inspectAsync()` lowers it to the **minimum** over the lexical base (`1.0`) and each successful probabilistic enricher finding's `confidence` (default `1.0`). With no enrichers it stays `1.0`, so `inspectAsync(url)` remains deep-equal to `inspect(url)`.
- `Reason.suppressed` is an OPTIONAL marker, present and `true` only when the caller's `suppressReasons` escape hatch (§8) matched that reason. It is **additive** and absent by default, so it needs no `SCHEMA_VERSION` bump: with no `suppressReasons` option every result is byte-for-byte identical to the pre-existing `1.1` output.

### 6.1 PSL snapshot provenance & staleness

linklint's core claim — "the real host is `evil.com`" — is computed from the
Public Suffix List bundled inside `tldts` (pinned via
`dataVersions.publicSuffixList`). A silently stale bundled PSL degrades
embedded-domain / brand-lookalike / ambiguous-authority reasoning with no signal
to callers, so the trust boundary carries its own provenance:

- **Provenance record** (`src/data/psl-provenance.ts`, `PSL_PROVENANCE`): a
  hand-captured `{ tldtsVersion, pslListDate, retrievedAt }` verified at
  dependency-pin time. `pslListDate` is the pinned `tldts` npm-release date used
  as the snapshot proxy — `tldts` regenerates its bundled list from upstream at
  release-build time, so the release date is a tight **upper bound** on the
  snapshot's age (staleness computed from it is conservative). Bump all three
  fields together with `dataVersions.publicSuffixList` on every `tldts` pin.
- **`pslOutdated(maxAgeDays = 180)`**: a **pure, offline** check reading only the
  provenance record → `{ stale, ageDays }`. Unknown/unparseable date →
  `{ stale: null, ageDays: null }` (undetermined, never assumed either way).
- **`result.pslSnapshot`**: `{ date, stale }` surfaced on every result so
  consumers learn the provenance of the boundary they were handed.
- **Freshness-corpus CI** (`test/freshness-corpus.test.ts`): pins the IMC '23
  (McQuistin et al., Table 2) multi-tenant eTLDs so a stale bundled PSL can never
  silently reintroduce the paper's tenant-collapse harm — two distinct tenants
  of `myshopify.com` etc. must not collapse to one registrable domain.

**Documented tradeoff — `allowPrivateDomains: false`.** `analyzeHost()`
(`parse/psl.ts`) resolves under ICANN-only rules **deliberately**, so an embedded
`github.io` is still seen as a registrable domain by FR-D-8. The consequence,
from the same IMC '23 paper, is that at the linklint layer private-suffix tenants
*do* collapse onto the ICANN registrable domain (`good.myshopify.com` and
`evil.myshopify.com` both resolve to `myshopify.com`). This is a conscious
tradeoff, **not** changed here; the freshness gate probes `tldts` with
`allowPrivateDomains: true` (the view where these eTLDs live) to test the bundled
*data's* freshness independently of that policy.

**Upstream conformance corpus (U2).** The freshness gate above answers "is the
bundled list recent?"; it does not answer "does the list still resolve the way it
did?". `test/psl-conformance.test.ts` closes that gap by running the **entire**
upstream `tests/tests.txt` (78 rows, vendored at
`test/data/psl-tests.txt` and pinned by `sha256`) against `analyzeHost()` on
every check — wildcards (`*.mm`, `*.ck`), exceptions (`!www.ck`, `!city.kobe.jp`),
deep nesting (`k12.ak.us`), uppercase, unlisted TLDs, and IDN labels in both
U-label and A-label form. **71 of 77 host rows match upstream verbatim (92.2%).**
The 6 that do not are enumerated in an exact ledger — an undeclared divergence
*and* a ledger entry that stopped diverging both fail — in two classes, each with
a positive proof rather than an allowlist entry:

1. **PRIVATE-section suffixes** (4 rows, the `uk.com` family). Upstream exercises
   the full list; linklint is ICANN-only per the tradeoff above. Proven to be
   exactly that flag: re-running those rows with `allowPrivateDomains: true`
   reproduces every upstream expectation.
2. **Leading empty label** (2 rows, `.example.com` / `.example.example`). `tldts`
   tolerates a leading dot; linklint's parser rejects an empty label first
   (`parse/raw-parts.ts`), so the input never reaches the PSL layer. Proven by
   asserting `inspect()` returns `status: "invalid"` for both — while a single
   *trailing* root dot still parses.

Neither class is a defect, and neither is silently allowlisted. A `tldts` pin
bump that moves any other row fails here, before it can surface downstream as an
unexplained scoring change.

**Decision — the boundary stays global, and the brand family stays ICANN-only.**
A per-detector boundary choice was investigated and **declined**. Three findings,
in order of weight:

1. **Switching the brand family to the PRIVATE-inclusive view fires nothing.**
   `brand_homoglyph` requires the digit-folded registrable domain to be an exact
   `BRAND_DOMAINS` member. Handed the PRIVATE-inclusive view, `paypa1.vercel.app`
   folds to `paypal.vercel.app`, which is not a watchlist domain. The widening on
   its own is inert — it would only *look* like coverage. (At the time this was
   measured, `brand_lookalike` — a bounded edit distance over the whole
   registrable domain — was also inert here, at distance far above 2 from
   `paypal.com`. It has since been deleted outright; see §6.1.2.)
2. **Making it fire means comparing the tenant label, which reopens a closed
   decision.** Reducing to the tenant label (`paypa1` → `paypal`) does match, but
   the same mechanism matches *any* tenant whose label is a brand label — and
   roughly two dozen of the 106 entries in `BRAND_LABEL_SET` are ordinary English
   words: `apple`, `amazon`, `visa`, `chase`, `oracle`, `uber`, `ledger`,
   `discord`, `telegram`, `blockchain`, `kraken`, `ups`, `stripe`, `slack`,
   `zoom`, `box`, `cash`, `live`, `meta`, `target`, `booking`, `wise`, plus the
   single character `x`. On platforms whose whole purpose is cheap tenant
   namespaces, `target.myshopify.com` and `cash.github.io` are unremarkable. That
   is the false-positive surface `LINK-blgvypxk` closed by deleting
   `brand_in_path` and `brand_combosquat` outright, and it would return by
   another route. Note that the generic-word guard which used to live in the
   `keywords` field of `data/brands.ts` was deleted alongside `BRAND_KEYWORDS`,
   while `BRAND_DOMAINS` kept those brands — so nothing currently prevents this.
3. **The exclusion list that would make it safe is itself a judgment call.**
   Which labels count as "ordinary words" cannot be settled by reading the list;
   it needs an adversarial corpus of unseen tenant labels, because a
   hand-curated benign set is self-confirming — precisely how the
   `brand_combosquat` false-positive surface stayed hidden until it was probed
   against unseen hosts (`LINK-cqdrdvfu`).

**Accepted limitation.** A brand-impersonating tenant on a PSL PRIVATE-section
platform is **not** detected: `paypal.myshopify.com` scores `0.00`/`info`, where
`paypa1.com` scores `0.60`/`high`. (The *digit-folded* half of this limitation —
`paypa1.vercel.app` at `0.20`/`low` — is **no longer true**: it now scores
`0.60`/`high`, the same band as `paypa1.com`. See §6.1.1 and `LINK-lippdgpn`.)
This is the same accepted-limitation class as `paypal-login.com`
scoring `0.00` — deliberate, and preferred over a detector that flags legitimate
tenants. The IMC '23 multi-tenant rows in `test/corpus/vectors.ts` (which forbid
`embedded_domain_in_subdomain` and `ambiguous_authority` on legitimate tenants)
are the standing tripwire against reintroducing this by another route.

> **Partly superseded — see §6.1.1 (`LINK-pblqdrco`).** The `paypal.myshopify.com`
> half of this limitation stands unchanged and permanently: exact-label matching
> stays rejected, and findings #2 and #3 above were re-tested and **confirmed**.
> The `paypa1.vercel.app` half — the *digit-folded* case only — was reopened with
> the unseen-tenant corpus finding #3 asked for, and **adopted**. Read the two
> entries together: what changed is not the boundary and not exact matching, only
> that a label whose digits fold to a brand label is now treated as the same
> disguise on both sides of the PRIVATE boundary.

**Unchanged:** FR-D-8 / `embedded_domain_in_subdomain` keeps ICANN-only
semantics, which is what the tradeoff above exists to protect.

**Declined (`LINK-mfpwgspt`).** Exposing *both* boundaries on `HostFacts` is
mechanically easy, but adds a second PSL lookup to every `inspect()` against the
sub-5 ms budget, plus a permanently wider type surface on which every future
detector picks between two similarly-named fields with a subtle correctness
difference and no compiler help. It was held open on the rule "build the seam
when a detector needs it" — the same rule applied to the `parse.ts` split — and
then the only candidate consumer was removed by the decision recorded above, so
the seam has no call site to serve. The PRIVATE-inclusive view is already
computed directly where it is genuinely needed (`test/boundary-baseline.ts`,
`test/freshness-corpus.test.ts`, `test/psl-conformance.test.ts`), none of which
this seam was blocking. If a detector ever does need it, refile: compute both
views in `analyzeHost()`, share once per `inspect()`, keep the existing field
bound to the ICANN-only value, and add no caching (pslr D19).

Note for anyone arriving from the accepted limitation above: escalating
`paypa1.vercel.app` does **not** require this seam. That question was
`LINK-pblqdrco`, now **decided and adopted** in §6.1.1 — and it was adopted on
exactly the path described here, joining the skeleton `ascii_homoglyph` already
computes to `BRAND_LABEL_SET` over the host labels: a set membership test, with
no PSL boundary involved. This seam stays declined; the adopted mechanism needs
no call site for it.

#### 6.1.1 Digits in labels — fold-gated brand escalation (adopted) and a general digits signal (declined)

Two independent questions, recorded together because they were raised together
(`LINK-pblqdrco`). The trigger was the 3x score gap in §6.1's accepted
limitation: `paypa1.com` → `0.60`/`high`, `paypa1.vercel.app` → `0.20`/`low`,
same disguise, same reading. `ascii_homoglyph` fires in both cases and its detail
already names the reading (`paypa1` reads as `paypal`); the whole delta is
`brand_homoglyph`, which never gets a look because it tests the *registrable
domain* and `paypa1.vercel.app`'s registrable domain is `vercel.app`.

**(a) Label-level fold-gated brand escalation — ADOPTED.**

The mechanism: for each host label that already passes `ascii_homoglyph`'s gates,
if folding its digits yields a `BRAND_LABEL_SET` member, escalate. A set
membership test over `ctx.hostLabels`. **No PSL boundary change** — the
`LINK-mfpwgspt` seam declined above is not a prerequisite and was not revived.

§6.1's finding #3 set the evidence bar: reasoning over our own brand list is
self-confirming, so this needs a corpus of *unseen* tenant labels. Four
measurements, in order of weight:

1. **The firing surface is finite, enumerable, and small.** Because the gate
   requires `fold(label) !== label` *and* an exact hit in `BRAND_LABEL_SET`, the
   complete set of labels that can ever fire is the set of valid pre-images of a
   brand label under the fold. Enumerated: **65 of 106** brand labels are
   fold-reachable, yielding **exactly 192 labels**. This is the decisive
   structural difference from every previously-rejected brand widening — it is
   not a heuristic with an open-ended surface but a list that can be read.
2. **Zero false positives on 36,200 unseen real tenant labels.** A GitHub login
   *is* the tenant label for `<login>.github.io`, so the login list is an
   unfiltered corpus of real multi-tenant labels. 7.3% contain a digit; **427
   (1.18%) pass `ascii_homoglyph`'s gates and already score `0.20`/`low` today**;
   **none folds to a `BRAND_LABEL_SET` member.** The reason is structural, and it
   is the crux: the common benign digit-in-label pattern is a *numeric
   suffix or counter* — `mwalker1`, `haru01`, `jramirez00` — which folds to
   gibberish (`mwalkerl`, `haruol`, `jramirezoo`). Firing requires a digit
   *mid-word, standing in for the letter that spells a brand*, which is the
   attack signature itself. Length equality under the fold also means no
   `shop1`-style label can ever reach a shorter brand label.
3. **Live probe of the entire surface: no legitimate tenants.** All 192 labels
   probed against `github.io`, `vercel.app`, `myshopify.com` (576 probes) — 25
   live. Classified by fetched title: impersonation (`app1e` → "Apple iPhone",
   `bank0famerica` → "Bank of America", `faceb0ok` → "Facebook", `paypa1` →
   "Paypal", `robl0x` → "Roblox Cookie Capture"), platform-suspended (`402`), or
   **legally taken down** (`bl0ckchain.vercel.app` → `451`). **Not one is a
   legitimate business operating under an unrelated name.** The ordinary-word
   brands that drove finding #2 — `apple`, `amazon`, `booking`, `telegram`,
   `blockchain` — appear here only as `app1e`, `amaz0n`, `b00king`, `te1egram`,
   `bl0ckchain`, and every live one of those is impersonation, suspended, or
   taken down.
4. **Control group — finding #2 was right, and this is not the same mechanism.**
   The identical probe against the 106 **unfolded** labels returns **127 live
   `200`s**, including the brands' *own official* orgs (`microsoft.github.io`,
   `google.github.io`, `adobe.github.io`, `cloudflare.github.io`,
   `netflix.github.io`, `oracle.github.io`, `stripe.github.io`,
   `salesforce.github.io`) and the ordinary-word tenants finding #2 named
   (`target.github.io`, `cash.github.io`, `box.github.io`, `uber.github.io`),
   plus 14 more at `451`. Exact-label matching has a ~40% live-tenant surface
   dominated by legitimate use — flagging it would flag brands impersonating
   themselves. The fold-gated surface is 4.3% and dominated by abuse. **That
   ~10x gap is the argument the standing "document-and-stop" rule required to be
   won rather than assumed:** the fold gate is a structural property of the
   input, not a curated exclusion list of the kind §6.1 finding #3 rejected.

**Residual risk, stated plainly.** Roughly 4–6 of the 25 live hits are
benign *by content* while being a brand look-alike *by name*:
`sa1esforce.vercel.app` and `salesf0rce.vercel.app` serve an unrelated "Brunch"
template, `g0ogle.github.io` is a personal page, `sh0pify.github.io` is Shopify
tutorial content. Escalating these to `high` is accepted, on consistency: the
ICANN-side `brand_homoglyph` already scores `paypa1.com` `high` without any
content evidence, because the claim it makes is *"this host's name is a
digit-disguised brand"* — which is true in 25 of 25 cases here — not *"this is
phishing"*. The alternative is to keep scoring the same disguise 3x differently
based on which side of a boundary the attacker rented space on.

**Tripwire gap found while testing this.** The IMC '23 multi-tenant rows named as
§6.1's standing tripwire contain **no digits** (`myshop.myshopify.com`,
`docs.readthedocs.io`, …), so they cannot fire under this mechanism either way
and provide **no protection against it**. Implementation must add rows that
actually bind: benign digit-bearing tenant labels that fold to gibberish
(`pete1.github.io`, `haru01.github.io` — both `0.20`/`low` today and must stay
there) alongside the positive `paypa1.vercel.app` case, plus a test asserting the
192-label surface is unchanged so a brand-watchlist addition cannot silently
widen it.

**Implemented (`LINK-lippdgpn`).** Filed as `LINK-tbqeqqvv` and delivered by
`LINK-lippdgpn`, which chose the **hyphen token** — not the whole host label —
as the unit of analysis, so one mechanism covers both `paypa1.vercel.app` and
`paypa1-login.com`. `brand_homoglyph` now runs two tiers, deduped so a host
matching both still emits exactly one reason: tier 1 the registrable domain
against `BRAND_DOMAIN_SET` (unchanged), tier 2 every `-`-separated token of
every host label against `BRAND_LABEL_SET` under the identical fold gate. It
reuses the existing `brand_homoglyph` reason code and changes no weight, so
neither `SCHEMA_VERSION` nor `WEIGHTS_VERSION` moved. The tripwire rows this
entry demanded (`pete1.github.io`, `haru01.github.io`) are in
`test/corpus/vectors.ts`, and the surface pin is
`test/brand-fold-surface.test.ts`. One behavioural difference from the mechanism
as sketched above: the escalation is **not** gated on the label first passing
`ascii_homoglyph`, so leading-digit folds (`0racle-support.com`) also fire — at
`0.50`/`medium` rather than `0.60`/`high`, exactly as `0racle.com` already did
on the registrable-domain tier.

**(b) A general digits-in-label signal — DECLINED, including as an optional knob.**

The premise — legitimate brands rarely put digits in domains, and digits are a
classic SEO-spam marker — does not survive contact with the corpus. **1.18% of
real tenant labels pass these gates**, roughly 1 in 85 hosts, and measurement 2
shows what they are: ordinary developer usernames with a counter (`pete1`,
`number5`, `snoozer05`, `jcoppedge1`, `testapi11`). Only 5.2% of them fold to
even a dictionary word. There is no precision floor to build on — the gates
select for *digit-in-word shape*, which is a necessary condition for the
disguise but nowhere near sufficient, and that is exactly why `ascii_homoglyph`
is weighted `0.2` and documented to "only matter in combination". Those 427
labels scoring `0.20`/`low` is the correct outcome, not a missed escalation.

Declined as an optional policy knob too, for a different reason: "digits in the
domain" is a ranking-quality preference, not a deception verdict, and belongs to
whatever consumer holds that preference rather than to a URL-deception linter.
The benign classes cited in the original request are already spared without any
new policy — `z100` and `kiss108` fail the letters-outnumber-digits and
unmapped-digit gates respectively, and `987fm` fails the leading-letter gate — so
a knob would buy no coverage the existing gates withhold. Revisit only if a
concrete consumer asks for it, and then as consumer-side policy over the
`ascii_homoglyph` reason code, which already carries the skeleton in its detail.

#### 6.1.2 Structurally-clean brand near-misses — deleted (`LINK-cphogucn`)

**Decision — `brand_lookalike`, `brand_soundsquat`, and `brand_bitsquat` are
deleted outright.** Removed in schema `1.4` / weights `1.13`. This is a
scope-of-claim correction, not a tuning change, and it is not about list size.

The claim and the rule this decision applies are stated canonically in
**§1.1** — claim (a) STRUCTURAL over claim (b) SEMANTIC, and the
name-never-create rule. Read that section for the reasoning and the supporting
literature; this section records only what the rule did to these three codes.

The three deleted detectors broke the rule. They fired on inputs where
`normalize(input) === input`:

| Deleted code | Example | Structural state of the input |
|--------------|---------|-------------------------------|
| `brand_lookalike` | `paypai.com` | pure ASCII, single script, no digits, no fold |
| `brand_soundsquat` | `netflicks.com` | pure ASCII, single script, no digits, no fold |
| `brand_bitsquat` | `netfliz.com` | pure ASCII, single script, no digits, no fold |

Nothing about these strings is anomalous. They are suspicious only relative to
knowing that `paypal` and `netflix` exist and are worth money — brand
intelligence, not URL structure. And they cannot be made to generalize: each
works for exactly the N hand-picked domains on the list and no others, forever.
This is the same disposition `LINK-blgvypxk` gave `brand_in_path` and
`brand_combosquat`, for the same reason.

**Survivors, and why they are different.** `brand_homoglyph` fires only when
`skel !== raw` — a digit demonstrably folded to a letter — and
`homograph_skeleton_collision` only when UTS#39 confusables are demonstrably
present. Both carry a structural precondition that is satisfied *before* the
watchlist is read; the list only names the target. Neither can fire where
`normalize(input) === input`. `brand_idna_collapse` and `brand_locale_collapse`
sit on the same footing: a divergence between two standards' readings is the
structural fact, and the brand match is the name for it.

**Accepted, deliberate loss of coverage.** `paypai.com`, `gogole.com`,
`netflicks.com`, `netfliz.com`, and `amazgn.com` all score `0.00`/`info`. That is
the intended outcome, asserted directly in `test/brand-lookalike.test.ts` and
carried as *benign* rows in the corpus so a future widening has to argue with
them. A free consequence: `anthropics.com` — Anthropics Technology Ltd, a real UK
business that sat at edit-distance 1 from `anthropic.com` — stops reading
`medium`/`0.40`.

**Consequence for the watchlist charter.** Fold-reachability is now the *only*
structural route onto `data/brands.ts`. The charter's former escape hatch ("a
stated non-fold justification — edit-distance or soundsquat coverage, say") no
longer names anything that exists; a brand label with no pre-images under the
ASCII digit fold buys nothing and should be declined.

**Naming debt (open).** The surviving check keeps the id `brand_lookalike` and
lives in `detectors/brand-lookalike.ts`, though it now emits only
`brand_homoglyph`. The families table above lists **check ids**, so that legacy
name is what appears there. Renaming the check id is a separate, mechanical
change (it moves `checksSkipped` strings) and was deliberately left out of this
unit.

### 6.2 IDNA / UTS-46 conformance & the normalization flag profile

Every verdict that rests on *"what host is this really"* flows through
`src/unicode/idna.ts`, backed by `tr46` (pinned as `dataVersions.idna`). tr46
embeds its own UTS-46 and Unicode data and releases on its own cadence, so the
same silent-drift exposure the PSL has applies here.

**Flag profile.** `idna.ts` passes only `transitionalProcessing`; every other
tr46 option keeps its default of `false` — **CheckBidi, CheckHyphens,
CheckJoiners, UseSTD3ASCIIRules and VerifyDnsLength are all off**. This is
deliberate: `inspect()` must *classify* hostile input, not reject it, so
normalization stays maximally permissive and the detectors decide what is
suspicious. A bidi-violating or over-long host is a finding, not a parse failure.

**Conformance gate (U1).** `test/idna-conformance.test.ts` runs the **entire**
upstream `IdnaTestV2.txt` (6,391 rows, Unicode 17.0, vendored at
`test/data/IdnaTestV2.txt` and pinned by `sha256`) against `toAsciiUnder()`
(both transitional and nontransitional), `toUnicode()`, `toAscii()` and
`hasMalformedPunycode()` on every check.

Rows are triaged using the corpus's **own** relaxation table, not a linklint
allowlist — the file's header states that an implementation leaving a flag false
"would ignore the corresponding status codes" (`VerifyDnsLength: A4_1, A4_2` ·
`CheckHyphens: V2, V3` · `CheckJoiners: Cn` · `CheckBidi: Bn` ·
`UseSTD3ASCIIRules: U1`, plus `X4_2` as the toUnicode counterpart of `A4_2`).
Every remaining code (`P*`, `V1`, `V4`, `V6`, `V7`, `A3`) is a hard error
linklint must still reproduce.

**Result: 100.00% on all three operations — zero divergences to document.** The
figure is kept honest by pinning the corpus shape alongside it: 4,181 rows must
still *fail* under this profile and 2,210 must *succeed*, of which 1,661 succeed
only because a flag is off. A relaxation rule that had quietly swallowed the
corpus would also report 100%, so the split is asserted too.

**Decision — compatibility folds get no signal distinct from `normalization_delta`.**
Investigated and **declined** (`LINK-qrktkbtg`). A host label can contain
compatibility-decomposable characters that fold to a different ASCII string than
they display as — `ﬁle.com` → `file.com`, `ｅxample.com` → `example.com`,
`ex⓪ample.com` → `ex0ample.com`. All currently score `info` 0.00 with
`normalization_delta` + `idna_mapping_ambiguity`, both weight 0. Three findings:

1. **The existing design already draws the right line, and it is finer than
   "contains a compatibility character".** The discriminator is *disagreement
   between standards*, not exotic input. A label that folds to the legitimate
   target under **both** IDNA2003 and UTS-46 reaches the genuine site and must
   not escalate (`ｇｏｏｇｌｅ.com` → the real `google.com`, pinned `info` in
   `corpus.ts` as J9 Group B). A label that folds *differently* depending on the
   standard, landing exactly on a watchlist brand, already escalates via
   `brand_idna_collapse` at weight 0.5 (`wordpreß.com` → `wordpress.com` under
   IDNA2003 but `xn--wordpre-6va.com` under UTS-46).
2. **The narrow alternative was tried and the corpus rejected it.** Making
   `idn_host` fire when the raw registrable domain is non-ASCII even though it
   folds to ASCII (`detectors/idn-host.ts` uses `toUnicode`, whose UTS-46 mapping
   erases the evidence) moved `ｇｏｏｇｌｅ.com` from 0.00 to 0.70 — one false
   positive, precision 1 → 0.992. That row is a deliberate decision, not an
   oversight, so the change is wrong rather than merely inconvenient.
3. Raising `normalization_delta` is not an option: weight 0 is required by
   FR-D-15, since every IDN trips it and a legitimate single-script IDN must stay
   benign.

**Accepted limitation.** A compatibility spelling of an *ASCII-homoglyph*
lookalike is not detected: `paypa１.com` (fullwidth digit one) scores 0.00 while
its folded twin `paypa1.com` scores 0.60 via `brand_homoglyph` + `ascii_homoglyph`.
Closing it would mean running the digit-fold homoglyph comparison on the
compat-folded host — stacking two fuzzy transforms, which is precisely the
combination whose false positives forced the `LINK-blgvypxk` rollback. Same
accepted class as `paypal-login.com` scoring 0.00.

**Unicode baseline.** The bundled tr46 carries **Unicode 17.0** data, evidenced
by CJK Extension J (`U+323B0..U+3347B`, assigned in 17.0, `disallowed` in 16.0):
running the 16.0 corpus against it produces exactly 13 failures at those code
points, and the 17.0 corpus produces none. Two assertions pin that baseline
directly, so a `tr46` pin that moves to a different Unicode release fails even
before the corpus is refreshed. Note this is a **newer** Unicode release than the
confusables table (16.0.0, `tools/build-confusables.mjs`); the two data sets are
independent and are pinned separately.

**The confusables pin deliberately stays at 16.0.0.** Aligning it to 17.0 was
measured and **declined** (`LINK-tydjfmci`). Unicode 17.0 adds `þ → p`, so a
Latin-script host whose only non-ASCII character is `þ` skeletons entirely to
ASCII and trips `homograph_latin_skeleton` (critical, weight 1.0):
`þingvellir.is` — a real Icelandic UNESCO site — goes from `info` 0.00 to
`critical` 1.00. The whole suite passed under the 17.0 table apart from the drift
guard, because the curated corpus contains no Icelandic: a hand-curated benign
corpus *confirmed* a bump that breaks real browsing, the same self-confirming
failure mode recorded after `brand_combosquat` (`LINK-cqdrdvfu`).
`confusables-drift.test.ts` carries the tripwire.

### 6.3 Pin-bump gate — diffing linklint's own answers

§6.1 and §6.2 both ask *"does linklint still agree with upstream?"*. Neither asks
the question that actually matters when bumping `tldts` or `tr46`: **did this
bump move an answer for a host linklint reasons about?** A change can be
perfectly conformant upstream — a genuinely new PSL rule, a newly-assigned code
point — and still silently redraw the registrable domain of a watchlist brand.

`test/boundary-baseline.ts` (run via `pnpm data:boundary`) records linklint's own
answers for a fixed, fully committed input set of **255 hosts**: every
`BRAND_DOMAINS` entry, every corpus vector host (extracted with linklint's own
parser, so U-labels survive), every host in the vendored upstream PSL corpus, and
the IMC '23 multi-tenant eTLDs with a tenant under each. For each host it records
both PSL views and both normalization modes:

| Recorded | Why |
|---|---|
| ICANN-only domain / suffix / subdomain | the view `inspect()` actually reasons with |
| PRIVATE-inclusive domain / suffix | the freshness-gated view (§6.1) |
| `isIcann` — **which section** the rule came from | a rule crossing the ICANN/PRIVATE boundary moves one view while leaving the other intact |
| U-label, toASCII transitional + nontransitional | `tr46` owns all three |

`pnpm data:boundary --check` diffs the committed baseline against what the
current pins produce and prints a **reviewable list of what moved** — section
moves called out first and separately — then exits non-zero.
`boundary-baseline.test.ts` runs it on every check, so an unreviewed bump cannot
land quietly, and its own negative-control tests mutate a cloned baseline to
prove each change class is really detected. Accepting a bump means regenerating
the baseline in the same commit; the bump checklist is in `CONTRIBUTING.md`.

This is the pattern pslr shipped as `psl_diff` (PSLR-ayahzscr) after surveying
PSL libraries across ten language ecosystems and finding none that offered
snapshot-to-snapshot diffing.

**On `pslSnapshot.stale` semantics.** pslr retired its boolean `psl_outdated()`
in 1.1.1 because a boolean conflates *content age* with *knowledge of the remote
endpoint*. linklint keeps the boolean, and the distinction is load-bearing:
`stale: false` means **"the bundled snapshot is under 180 days old"** — it does
**not** mean "verified current against publicsuffix.org". linklint has no network
path and never contacts the upstream list, so a bundled snapshot can be
`stale: false` and still be missing rules added last week. `stale: true` is a
prompt to consider bumping the pin; `stale: false` is *not* a freshness
guarantee, and `null` means the snapshot date is unknown — undetermined, never
assumed either way.

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
  Structured enrichment findings use their outcome's actual URL/host subject;
  allowing the original host never suppresses a discovered destination.
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
| `packages/online` | Explicit Node/server capabilities; L0 safe transport and L2 local wrappers shipped | `@linklint/online` |

Planned but not yet built: browser extension, GitHub Action, REST/serverless wrapper. The rule is the same for all of them: call `inspect()`, present the result, enforce policy at the adapter — never fork detector logic.

Concrete online work follows a stricter package boundary. Pure enrichment
contracts and orchestration remain in `linklint`; DNS-pinned destination
transport, resolution, provider adapters, and caller-owned mirror integrations
live in the Node-only `@linklint/online` sibling package; long-running
monitoring owns a separate deployable service and durable state. The existing
CLI and MCP packages remain offline, and browsers delegate authorized online
work to a caller-owned backend because browser fetch cannot enforce the L0
socket and DNS-pinning controls. The accepted decision, export categories,
dependency direction, consent, secret, licensing, and migration rules are in
[`online-runtime-boundary.md`](online-runtime-boundary.md).

The online package exposes L0 through `@linklint/online/transport`. Its
exact-URL authorization, all-answer address policy, DNS-pinned socket,
original-host TLS identity, fresh header set, manual redirects, cumulative
budgets, and structured outcomes are documented in
[`safe-transport.md`](safe-transport.md). The internal LT harness remains the
zero-external-network acceptance seam for resolver changes, connector identity,
streamed HTTP, failures, and deterministic deadlines.

Exact local Microsoft Safe Links and Proofpoint URL Defense decoding is exposed
through `@linklint/online/resolution`. It is separately bounded, never calls a
vendor decoder service, and re-inspects every recovered destination through the
offline pipeline. See [`wrapper-decoding.md`](wrapper-decoding.md).

The same subpath exposes bounded redirect and declarative-refresh expansion.
Every initial request and discovered target receives a separate caller
authorization decision and passes through one cumulative L0 session. Only
GET/HEAD and 301/302/303/307/308 are followed; HTTP Refresh and HTML meta refresh
share byte, MIME, charset, delay, and hop limits, and JavaScript is never
executed. Every target is inspected offline before the chain continues, ordered
hop evidence is retained, and only the worst fetched hop projects de-duplicated
findings. See [`redirect-chain-resolution.md`](redirect-chain-resolution.md).

## 10. Layer model

The three-layer model is a forward-compatibility contract:

| Layer | Status | Description |
|-------|--------|-------------|
| **Lexical** (L1) | **Implemented** | Offline, deterministic, synchronous. 36 checks: 4 structural, 32 parsed (5 of them agent-gated). < 5 ms typical. |
| **Resolution** (L2) | **Partial** | Exact local wrapper decoding and caller-authorized bounded redirect/refresh expansion are implemented; observed correlation/divergence and MIME evidence remain roadmap work. Every discovered target is re-inspected through L1. |
| **Reputation** (L3) | Roadmap | Threat feeds, RDAP domain age, CT, DNS posture. Privacy-preserving by design. |

L2 and L3 extend `checksRun` / `checksSkipped` — they add to lexical results,
never replace them. Unconfigured or incomplete sources remain explicit, so a
score never implies that unfinished resolution or reputation work was clean.

**Result cache (opt-in).** So networked enrichers don't re-hit third parties on every call, `inspectAsync` accepts a pluggable `EnrichmentCache`; `get`/`set` may be synchronous or Promise-capable, and `InMemoryEnrichmentCache` is the dependency-free default. Only runtime-validated structured reports are stored and every hit is revalidated. An enricher opts in with `cacheKey(result, context)` plus a positive static `cacheTtlMs`, a response-driven `cacheTtlMsFor(report, context)`, or both. Dynamic TTLs allow explicit no-hit results to use shorter negative-cache lifetimes; failures, skips, and partial reports are never cached. A hit skips the provider call but still counts as a run (`<layer>:<id>` in `checksRun`). **Privacy:** the framework never derives caller key material from the full URL, rejects direct full-URL leakage, and wraps the caller's projection in an opaque schema/source namespace. The adapter must still use a privacy-preserving projection (registrable domain, local-mirror ID, one-way hash-prefix), never reconstructible URL material.

**Bounded runner and per-source governor.** Every configured enricher is hard-bounded by the runner at 5000 ms by default, even when no governor is supplied. A positive finite `Enricher.timeoutMs` overrides the bound; `null` is the only explicit opt-out and is intended for callers with an outer hard deadline. Non-positive/non-finite values retain the safe default. Timeout aborts the composed context signal and wins a runner-level promise race even when an enricher ignores cancellation; the abandoned promise stays observed so a late rejection is handled. Promise-capable cache reads/writes are awaited behind the same source timeout policy and late rejections remain observed. `inspectAsync` also accepts an optional stateful `EnrichmentGovernor` (`InMemoryEnrichmentGovernor` is dependency-free with an injectable clock) for (1) a **token-bucket rate limit** and (2) **exponential backoff**, both keyed by `<layer>:<id>` and persisted when the instance is shared. The governor can additionally override/disable the timeout policy. Its built-in denial decisions distinguish `rate-limited` from `backoff-active`. **Ordering (cache-before-governor):** a cache HIT consumes no token and touches no backoff because no network happened; only a MISS is admitted, consuming exactly one token. All enricher, cache-key, dynamic-TTL, cache, and governor calls are guarded. Exceptions become source-attributed structured degradation outcomes rather than escaping `inspectAsync`; valid provider evidence is retained alongside auxiliary TTL/cache-write/governor-lifecycle failures, making partial coverage explicit in both `checksRun` and `checksSkipped`.

**Staged orchestration.** The caller-ordered `EnrichmentPlan` is the existing
`enrichers` list plus optional `Enricher.dependsOn` `<layer>:<id>` edges. The
runner derives stable topological stages: independent steps in one stage run in
parallel over the same prior-outcome snapshot, while fan-in waits until every
declared prerequisite wholly completes. `EnrichmentContext.previousOutcomes`
carries every earlier structured status in plan order. Skipped, failed, or
partial prerequisites produce an explicit `prerequisite-unavailable` skipped
outcome; invalid/duplicate edges and cycles also degrade explicitly. Final
serialization stays in caller plan order regardless of promise completion order.
No dependency declarations preserves the original single parallel stage.

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
- `inspect()` never throws — unparseable input returns `status: "invalid"`. The
  guarantee is unconditional: a **non-string** argument (a plain-JS caller, or
  `JSON.parse` output handing back `null`) also returns `invalid` rather than a
  `TypeError`, since an uncaught throw in a calling hook fails *open*.
- Every finding has a named reason code with a human-readable `detail` string.
- Channels do not implement detectors.
- `normalization_delta`, `confusable_char`, and `confusable_in_path` are always informational (weight 0).
- Skipped lexical scoring detectors make the score a lower bound; fail-closed consumers must detect and handle `checksSkipped` entries matching `lexical:*`.
