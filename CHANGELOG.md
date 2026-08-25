# Changelog

All notable changes to this project will be documented here.

## Unreleased

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
