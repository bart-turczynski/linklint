# Changelog

All notable changes to this project will be documented here.

## Unreleased

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
