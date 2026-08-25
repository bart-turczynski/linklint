# Changelog

All notable changes to this project will be documented here.

## Unreleased

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
