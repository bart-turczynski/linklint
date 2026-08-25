# Changelog

All notable changes to this project will be documented here.

## Unreleased

### Removed — BREAKING (package API + result contract)

- **Delete `risky_tld` and `bait_tokens`, the whole "Contextual signals"
  detector family.** `SCHEMA_VERSION` `1.9` → `1.10`, `WEIGHTS_VERSION` `1.18` →
  `1.19` (`LINK-brsntven`, architecture §6.1.5). Both created a *scoring*
  finding from curated membership alone: `risky_tld` was a public-suffix
  presence check plus `RISKY_TLDS.has(tld)` over sixteen high-abuse registries,
  and `bait_tokens` counted distinct members of a seventeen-word English lexicon
  across host and path. §1.1's name-never-create rule says a curated table may
  NAME a structural anomaly and may not CREATE one, and neither detector did
  anything else. `mycompany.tk` and `secure-account-verify-login.com` each read
  `0.15`/`low` and now read `0.00`/`info`.
- **Not re-grounded at weight 0, unlike `credential_harvesting`.** §6.1.4's test
  is to strip the world-claim and ask what string fact remains. For `risky_tld`
  the residue is "the public suffix is `tk`", which `parsed` already carries;
  for `bait_tokens` it is "the host contains English words". The weight-0 slot
  for the TLD judgment already belongs to the caller (`denyTlds` → `tld_denied`).
- **Breaking package change on top of the schema bump.** `RISKY_TLDS` and
  `isRiskyTld` were public exports asserted by `public-api-contract.test.ts`, as
  were the `riskyTld` and `baitTokens` detectors on `linklint/experimental`. All
  four are gone. `packages/core/src/data/risky-tlds.ts` is renamed
  `data/file-extension-tlds.ts`; `FILE_EXTENSION_TLDS` / `isFileExtensionTld`
  are unchanged and still exported.
- **`DataVersions.riskyTlds` is RENAMED, not deleted** — to
  `DataVersions.fileExtensionTlds`, value carried forward unchanged. It is the
  only pin covering `FILE_EXTENSION_TLDS`, a live weight-`0.4` scoring table, and
  dropping the field would strand it against NFR-DATA-1. `SCHEMA_VERSION` owns
  the rename because `DataVersions` is part of the serialized result (§6.4).
  Swept through `tools/check-upstream.ts`, `tools/README.md` and
  `tests/unit/check-upstream.test.ts`, which name the stamp as the exemplar
  curated snapshot.
- **Delete `packages/core/src/data/oauth-providers.ts`.** It existed only to
  gate `credential_harvesting` off on twenty-one curated identity providers — an
  inverse watchlist, the api-brands structure run backwards, forbidden in either
  polarity.

### Changed

- **The three agent-mode dispositions §1.1 recorded as *owed* are shipped.**
  `prompt_injection_url` `0.50` → `0`, `data_exfiltration` `0.30` → `0`,
  `credential_harvesting` `0.35` → `0` (`LINK-brsntven`, applying
  `LINK-uyoocslu`). All three still REPORT under `agentMode`, with their full
  detail strings; none of them scores. `credential_harvesting` now reports the
  authorization-code / token-flow shape for **every** host, `github.com`
  included, and its detail no longer asserts that the host is not a real
  provider. The consequence, stated in §1.1 and asserted in
  `packages/core/test/semantic-tier-retirement.test.ts`: **agent mode can no
  longer raise a score above what plain mode gives, except through
  `ssrf_cloud_metadata`** — the one gated code whose underlying fact is settled
  with the gate off.
- **`embedded_domain_in_subdomain` deliberately stays at `0.50`.** Two rows
  cross the shipped `--fail-on high` default on this change
  (`login.paypal.com.account.evil.com` and `login.paypal.com.evil.tk`, both
  `0.575`/`high` → `0.500`/`medium`), because the detector sits EXACTLY on the
  medium/high edge and its only companion was a `0.15` contextual signal.
  Raising the weight was measured and refused: eleven distinct corpus inputs
  carry the code and nine of them now read exactly `0.500` with no companion, so
  any raise above the boundary moves all nine into `high` — seven new failures
  against a default `--fail-on high` run, to restore two. See
  §6.1.5 for the full argument; both rows are pinned at their new bands so a
  future re-raise has to argue with them.
- **CLI: new `--deny-tld <tld>` and `--allow-tld <tld>`, both repeatable.**
  `packages/cli/src/args.ts` shipped zero policy flags, so "the caller supplies
  the TLD judgment" — §1.1's answer, and the reason `risky_tld` could go — was
  not true in practice for the tool's main surface. They emit the existing
  weight-0 `tld_denied` / `tld_not_allowlisted` policy codes and never move the
  deception score. Both policy summaries in `schema/reason-codes.ts`, which
  named the deleted detector, are rewritten.
- **Corpus: four benign rows added on free-registry TLDs** (`mycompany.tk`,
  `.ml`, `.xyz`, `.top`). The corpus had **none**, which is why `risky_tld`'s
  false-positive surface was invisible to the harness and the measured cost of
  deleting it read as zero for the wrong reason. The `bait_tokens` FP guards were
  CONVERTED from `forbidReasons` rows to plain benign rows rather than dropped —
  same disposition §6.1.4 gave the V4e guards — and the two deceptive rows that
  existed only to exercise the deleted detectors were removed, so recall stays
  `1.000`. Precision and recall are `1.000` / `1.000` before and after. Every
  row was inspected THREE ways — its own declared options, `agentMode` forced
  off, forced on — and all 1 040 → 1 055 verdicts diffed: **41 change, 6 of them
  with the gate forced off.** Those 6 are the deletion and nothing else; the
  other 35 are the agent dispositions, confined to a mode the caller asks for.
  All are named in §6.1.5.
- **Docs.** `docs/architecture.md` §5 loses the whole "Contextual signals"
  family (seven families → six, 38 checks → 36, 34 parsed → 32); §1.1's
  disposition table is restated from *owed* to shipped, with its weight-quoting
  drift guard unchanged and now demanding `0.00` on three rows; §6.1.5 is the new
  deletion record. `docs/reason-codes.md` replaces both entries with deletion
  notes. `docs/scoring.md`: 40 scoring codes → 35, 17 zero-weight → 20.
- The mechanical `REASON_CODES` pin in
  `packages/core/test/docs-validation.test.ts` was confirmed RED on this
  two-code removal before the bumps were applied —
  `{ added: [], removed: ["bait_tokens", "risky_tld"] }` — which had previously
  been demonstrated for an addition and for a single-code removal.

- `data_exfiltration` no longer treats the bare word `data` as an exfiltration
  marker. `?data=report2024` on an ordinary download link scored 0.30/medium;
  it now scores 0.00. Package-semantics only under §6.4 — no `SCHEMA_VERSION`,
  `WEIGHTS_VERSION` or `DataVersions` move, because the result *contract* is
  unchanged and the code, its weight and its other five markers all remain.
  All 841 corpus verdicts were compared in both modes before and after: the
  removed false-positive class is the only difference (`LINK-uyoocslu`).


- **New `TRANSPORT_SCHEMA_VERSION` (`1.0`) and a runtime registry for the
  `@linklint/online/transport` outcome surface.** `TransportCauseCode` (30
  values) and `TlsObservationCauseCode` (18) were TypeScript unions and nothing
  else: erased at build time, so a consumer could not enumerate them, check a
  deserialized value against them, or detect that one had moved. The only
  runtime code sets in the package were `STABLE_OPERATION_CODES` (13 of 30) and
  `STABLE_OBSERVE_CODES` (7 of 18) — module-private proper subsets that map an
  adapter's `error.code`, not registries of the domain.
  `packages/online/src/transport/outcome-registry.ts` now exports all six closed
  domains of the subpath (`TRANSPORT_OUTCOME_STATUSES`, `TRANSPORT_CAUSE_CODES`,
  `TLS_OBSERVATION_OUTCOME_STATUSES`, `TLS_OBSERVATION_CAUSE_CODES`,
  `TLS_CERTIFICATE_DEFECTS`, `CERTIFICATE_ASSURANCE_LEVELS`) as frozen sorted
  arrays with matching type guards, and `docs/safe-transport.md` publishes the
  same six enumerations — which is what makes them CLOSED under the §6.4 rule
  that closedness is decided by the documented registry rather than the
  TypeScript annotation. The two adapter-mapping subsets keep their narrower job
  and are pinned as subsets.
- **The stamp is new rather than folded into `ENRICHMENT_SCHEMA_VERSION`.** That
  stamp owns core's structured enrichment report and its FRAMEWORK cause
  vocabulary; `schema/enrich.ts` states that adapters supply their own
  source-specific `EnrichmentCause.code` values and that the framework union
  covers only orchestration, cache, governor, and provider-call states. Transport
  causes reach a report through exactly that adapter channel
  (`redirect-chain.ts` copies `outcome.cause.code` verbatim), so folding them in
  would widen a core-owned stamp over a vocabulary core disclaims and cannot see
  — and the dependency arrow forbids it anyway, since `@linklint/online` depends
  on `linklint` and not the reverse. `SCHEMA_VERSION` stays put: a transport
  outcome is not part of the serialized `InspectResult`. Recorded honestly: no
  runtime code branches on `TRANSPORT_SCHEMA_VERSION` and no version-checking
  validator ships with it, because there is no caller for one. It is a
  consumer-facing declaration whose only in-repo reader is its pin test.
- The guard is the §6.4 mechanical pattern, not a prose grep:
  `packages/online/test/transport-outcome-registry.test.ts` checks in the six
  sorted key sets beside the stamp and asserts added/removed empty plus version
  equality, and it was proved to bite in BOTH directions before landing — RED on
  adding a cause value with the stamp left at `1.0`
  (`{ added: ["quic-handshake"], removed: [] }`) and RED on removing one
  (`{ added: [], removed: ["http-reset"] }`). It also pins the doc enumeration
  against the exported one, pins both adapter subsets as proper subsets, and
  pins `retryableTransportCause` in `redirect-chain.ts` — which re-lists ten
  transport cause codes by hand behind a `code: string` parameter and would have
  answered `false` for a renamed code with nothing red.
- **Delete `api_endpoint_impersonation` and `packages/core/src/data/api-brands.ts`**
  (`LINK-eurtxkit`, rescope carried 2–1). The detector fired on
  `API_BRAND_DOMAINS.get(token)` — a lookup into a hand-kept watchlist of ten
  commercial API providers — corroborated only by an exact `api`/`apis` token in
  a host label or one of four fixed route prefixes. Both corroborating signals
  are ordinary URL syntax available to any site, so neither supplies a
  structural precondition: the watchlist lookup WAS the finding, which
  `docs/architecture.md` §1.1 calls claim (b) wearing claim (a)'s clothes. The
  control is `api.acme-login.com` — the same string shape as
  `api.openai-login.com` in every respect a URL parser can see, and it always
  read `0.00` while the `openai` row read `0.50`/`medium`. Removed with it: the
  detector module, the data tier, the registry and descriptor entries, the
  reason code, the weight, the `docs/reason-codes.md` entry, the
  `docs/scoring.md` table row, and the two corpus positives (converted to benign
  rows, not dropped, so the accepted loss of coverage is recorded). The V4e
  false-positive guards were likewise converted from `forbidReasons` rows to
  plain benign rows, and `api.openai-login.com` plus its `acme` control were
  added. Check total 39 → 38, parsed 35 → 34, agent-gated 5 → 4.
  `data_exfiltration` is deliberately NOT in scope — it consults no data table
  and sits under `LINK-uyoocslu`. Recorded in `docs/architecture.md` §6.1.4.
- One scored row moves DOWN, and that is the point:
  `api.openai.com.evil.io/v1/chat/completions` was `0.50`/`medium` in plain mode
  from `embedded_domain_in_subdomain` and `0.75`/`high` under `agentMode`,
  because the deleted detector re-read the SAME `openai` label the structural
  finding had already scored and stacked a second `0.50` on it. Both modes now
  agree at `0.50`. Nothing outside the api-brand class moved: corpus precision
  and recall stay 1.000/1.000, and `api.0penai.com/v1/chat/completions` still
  reads `0.80`/`high` in PLAIN mode from `brand_homoglyph`, which stands on a
  demonstrated digit-to-letter fold rather than on a list.
- **`SCHEMA_VERSION` 1.8 → 1.9** and **`WEIGHTS_VERSION` 1.17 → 1.18**, owed by
  the deletion above under the §6.4 bump matrix: removing a value from
  `ReasonCode` is a change to a CLOSED, publicly exported domain, and removing
  its weight moves the weights map. The mechanical guard in
  `packages/core/test/docs-validation.test.ts` had only ever been demonstrated
  to bite on an ADDITION (the 1.7 → 1.8 bump below); it was deliberately run
  here on the REMOVAL with both stamps untouched, and failed with `removed:
  ["api_endpoint_impersonation"]` and the instruction to bump and re-stamp. Both
  directions of the closed domain are now known-guarded. Both constants
  (`PINNED_SCHEMA_VERSION`, `PINNED_REASON_CODES`) are re-stamped in the same
  commit. `ENRICHMENT_SCHEMA_VERSION` does NOT move.
- Name the HTTPS → HTTP downgrade a resolved chain walks into
  (`https_downgrade_observed`, `LINK-emlbzwct`). The fact was already fully
  derivable from the shipped `resolution.chain-hop` payloads — each carries
  `transport.protocol` for the hop it fetched and the ordered
  `transition.targetUrl` it was sent to — but nothing stated it, so a consumer
  had to reconstruct the scheme sequence to learn that a chain left TLS. The
  finding is raised on the hop that ISSUED the transition, once per downgrading
  transition, for all three mechanisms (HTTP redirect, `Refresh` header, HTML
  meta refresh), with a `resolution.https-downgrade` evidence record. The
  discriminator is the TRANSITION, never a hop's scheme: an `http://` input at
  hop 1 is an ordinary plaintext origin, and an upgrade or an `https:`→`https:`
  hop is nothing. **Weight 0, and not as a placeholder** — a downgrade is not
  deceptive under `docs/architecture.md` §1.1: the chain plainly says `http://`
  and no two readers disagree about what it says. It is reported under the
  fourth rule (report what you can determine, never silently pass), not scored.
  **The chain is never stopped and there is no option to stop it** (decided 2–1):
  refusal buys no confidentiality, because L0 sends no body, no cookie jar and no
  credentials and strips the caller's `Referer`, while it costs detection,
  because a refused hop is never fetched and the worst-hop projection, the
  open-redirect correlation and the MIME evidence all read fetched hops only.
- **`SCHEMA_VERSION` 1.7 → 1.8**, owed by the entry above under the §6.4 bump
  matrix: `https_downgrade_observed` is a new value in `ReasonCode`, a CLOSED,
  publicly exported domain enumerated by `REASON_CODES` and
  `docs/reason-codes.md`. This is the first bump taken under that matrix, and
  the mechanical guard shipped with it did its job — registering the code with
  `schema/base.ts` untouched failed
  `packages/core/test/docs-validation.test.ts` with `added:
  ["https_downgrade_observed"]` and the instruction to bump and re-stamp, which
  is exactly the shape of the `5813e01` miss the pin was written for. Both
  constants (`PINNED_SCHEMA_VERSION`, `PINNED_REASON_CODES`) are re-stamped in
  the same commit. `ENRICHMENT_SCHEMA_VERSION` does NOT move: evidence `type` is
  documented source-defined and open, so `resolution.https-downgrade` adds no
  value to a closed domain.
- Settle when `SCHEMA_VERSION` bumps (`LINK-zzydqrkd`). The repository stated two
  incompatible rules: `packages/core/src/schema/base.ts` claimed every contract
  change including additive ones, while `schema/options.ts`,
  `docs/architecture.md` §6 and `docs/scoring.md` each excused the additive
  `Reason.suppressed` field from a bump. `base.ts` is the rule that stands; the
  other three sentences are deleted. The adopted matrix is
  `docs/architecture.md` §6.4: `SCHEMA_VERSION` owns the serialized
  `InspectResult` — fields, nullability, documented meanings and CLOSED value
  domains, additive changes included; `ENRICHMENT_SCHEMA_VERSION`,
  `WEIGHTS_VERSION` and `DataVersions` keep their existing narrower ownership;
  the package version and this file own everything else. Closedness is decided
  by the documented registry, not by the TypeScript annotation, so `Reason.code`
  being typed `string` on the wire does not open the `ReasonCode` domain.
- Name two historical misses of that rule rather than baselining them in
  silence. **(1)** `Reason.suppressed` and the `suppression` `checksRun` token
  entered the contract in `a077eeb` (K5, `LINK-qowyxkem`) with
  `schema/base.ts` untouched: the schema read `1.1` before and after, and under
  the matrix a serialized field addition owed a bump. **(2)** `5813e01`
  (`LINK-fboctpse`) added the `fqdn_root_label` reason code with
  `packages/core/src/schema/base.ts` and `packages/core/src/scoring/weights.ts`
  BOTH untouched — a key entered the closed, publicly exported `ReasonCode`
  union, and the derived `WEIGHTS` map surfaced through `dataVersions.weights`,
  with neither stamp moving. That commit documented the new code in
  `docs/reason-codes.md` and `docs/scoring.md`, so every doc-sync assertion
  stayed green. Neither miss is retro-bumped, and the sole reason is that every
  package is an unpublished `0.1.0-dev.0`: no released consumer ever pinned
  `1.1` or `1.7` against the shape it actually received. Schema `1.7` is
  therefore the **reconciled baseline** — the version the current fields and the
  current 57-code registry are pinned to — and not a claim that every past
  change was stamped correctly.
- Pin the `REASON_CODES` key set to `SCHEMA_VERSION` in
  `packages/core/test/docs-validation.test.ts`. A prose grep for "no
  `SCHEMA_VERSION` bump" is the weak guard — three such notes in
  `docs/architecture.md` (§6.1.1, §6.1.2, §6.3) are correct under the matrix, so
  a grep cannot separate them from a defect. The mechanical pin can: the key set
  is checked in beside the version it registered under, so adding, renaming or
  removing a reason code without moving `SCHEMA_VERSION` fails, and moving
  `SCHEMA_VERSION` without re-stamping the pin fails too. It is the assertion
  that would have caught `5813e01`.
- Rename the brand-proximity check id `brand_lookalike` to `brand_homoglyph`,
  matching the single reason code it has emitted since the edit-distance step was
  deleted. The module is now `detectors/brand-homoglyph.ts` and the experimental
  export is `brandHomoglyph` (was `brandLookalike`, renamed without a deprecated
  alias — both packages are unpublished). No `SCHEMA_VERSION` bump: the result
  shape is unchanged and the id reaches `checksSkipped` only as
  `lexical:brand_homoglyph` on the detector-threw fault path.
- Fix `homograph_latin_skeleton` and `homograph_skeleton_collision` missing every
  punycode-spelled homograph: both read the registrable domain as written, so an
  `xn--` host was pure ASCII and failed their non-ASCII guard before any skeleton
  work ran. `https://xn--80ak6aa92e.com/` (`аррӏе.com`, an all-Cyrillic
  apple.com) scored `info` 0.00 where its Unicode twin scored `critical` 1.00.
  Both detectors now canonicalize to Unicode first, matching `idn_host`. Reachable
  under `idnPolicy: "allow"` / `--allow-idn` / `--idn-allow` — the documented
  override for legitimate IDN owners; under the default `block` policy `idn_host`
  still caught these at `high`.
- Make enrichment caches Promise-capable and schema/source-namespaced, store and
  revalidate only normalized structured reports, add response-driven
  `cacheTtlMsFor` lifetimes (including explicit no-hit negative caching), and map
  asynchronous store/TTL failures to bounded machine-readable degradation.
- Bound every configured enricher by default and isolate provider, cache,
  cache-key, governor admission, and governor lifecycle failures as structured
  per-source outcomes without discarding valid sibling/provider evidence.
- Add deterministic staged enrichment orchestration with per-enricher dependency
  tokens, accumulated prior outcomes, explicit prerequisite/plan/cycle skips,
  stable fan-out/fan-in serialization, and subject-aware finding suppression.
- Bump the result schema to 1.3 and add optional, versioned structured enrichment
  outcomes/evidence for `inspectAsync()`, including source identity validation,
  explicit success/no-hit/skipped/failure states, JSON-safe payloads, preserved
  provenance/freshness, and a compatibility adapter for legacy finding arrays.
