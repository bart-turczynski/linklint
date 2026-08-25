# Guarantee register

Every unconditional claim this repository publishes — **never**, **always**,
**unconditional**, **guarantee**, **invariant** — enumerated, classified, and
either pinned by a test or explicitly qualified.

## Why this exists

`LINK-zsbeqtcr` found an unqualified "`inspect()` never throws" in
`docs/architecture.md` and `README.md` that was **false**: `inspect(null)` threw
a `TypeError`. The claim had been published for weeks. Nothing in the repository
could contradict it, because nothing tested it.

Fixing that one claim did not answer the question it raised: *which other
guarantees are load-bearing prose with nothing behind them?* This register is
that answer, and the ratchet below is what keeps it answered.

The rule, stated once:

> **A guarantee is either pinned by a test or qualified in the prose.** An
> unconditional word with neither is a defect, not a stylistic choice.

This is the same doctrine as the decision-record trailer rule in
[`AGENTS.md`](../AGENTS.md): present-tense prose is a claim about what the code
does, and it must not outrun the code.

## The ratchet

`packages/core/test/guarantee-register.test.ts` enforces three things, so the
register cannot rot the way the claims it tracks did:

1. **Claim budget.** It re-extracts every line matching the guarantee-word
   pattern across `docs/` and the four package READMEs and compares the
   per-file counts to the budget table below. Adding or removing an
   unconditional claim fails `pnpm check` until the register is updated —
   which forces the triage to happen at authoring time.
2. **Pin integrity.** Every test path named in the *Pinned by* column must
   exist.
3. **Exemplar coverage.** Every negative exemplar in the §G audit must appear
   in at least one test file.

The register itself is excluded from its own budget: it quotes the claims it
tracks.

### Claim budget

| File | Claim lines |
| --- | --- |
| `docs/architecture.md` | 47 |
| `docs/bundle-size-budget.md` | 0 |
| `docs/enforcement.md` | 0 |
| `docs/enrichment-outcomes.md` | 12 |
| `docs/layer3-reputation-model.md` | 12 |
| `docs/local-workflow.md` | 3 |
| `docs/locale-case-mapping.md` | 4 |
| `docs/online-composition-root.md` | 1 |
| `docs/online-roadmap.md` | 12 |
| `docs/online-runtime-boundary.md` | 10 |
| `docs/online-source-contract.md` | 14 |
| `docs/raw-url-tokenization-spike.md` | 1 |
| `docs/reason-codes.md` | 83 |
| `docs/redirect-chain-resolution.md` | 4 |
| `docs/safe-transport.md` | 11 |
| `docs/scoring.md` | 6 |
| `docs/tracker-hygiene.md` | 3 |
| `docs/wrapper-decoding.md` | 1 |
| `README.md` | 14 |
| `packages/cli/README.md` | 1 |
| `packages/core/README.md` | 2 |
| `packages/mcp/README.md` | 2 |
| `packages/online/README.md` | 4 |

## A. Public API contract

The load-bearing class: claims a library caller relies on without reading any
detector.

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| A1 | `inspect()` never throws — unconditionally, including non-string input | `README.md`, `packages/core/README.md`, `docs/architecture.md` §9, `docs/reason-codes.md` (`parse_error`) | `packages/core/test/non-string-input.test.ts` |
| A2 | `inspect()` is synchronous — it returns a result, not a `Promise` | `docs/architecture.md` §0, `packages/core/README.md` | `packages/core/test/public-api-contract.test.ts` |
| A3 | Deterministic — same input + same package version → same verdict, with no state carried between calls | `README.md`, `docs/architecture.md` §0 | `packages/core/test/public-api-contract.test.ts` |
| A4 | Core opens no network connection, does no filesystem I/O, and emits no telemetry | `README.md`, `docs/architecture.md` §0 | `packages/core/test/runtime-compat.test.ts` |
| A5 | `inspectAsync()` with no enrichers is deep-equal to `inspect()` | `docs/architecture.md` §7, `docs/enrichment-outcomes.md` | `packages/core/test/inspect-async.test.ts` |
| A6 | `confidence` is `1.0` for every deterministic lexical result and never feeds score aggregation | `docs/architecture.md` §7 | `packages/core/test/public-api-contract.test.ts` |
| A7 | Reason ordering is locale-independent (no `localeCompare`, no `Intl.Collator`) | `docs/locale-case-mapping.md` §1 | `packages/core/test/locale-independence.test.ts` |
| A8 | A new reason code never enters the `REASON_CODES` registry without a `SCHEMA_VERSION` bump | `docs/architecture.md` §6.4, `packages/core/src/schema/base.ts` | `packages/core/test/docs-validation.test.ts` |

**A3's antecedent named the wrong stamp, and was false until this correction.**
It read "same input + same pinned **data versions** → same verdict".
`5813e01 (LINK-ephrdynz)` added the `fqdn_root_label` detector and its reason code — changing
`reasons[]` for every fully-qualified host input — with
`packages/core/src/schema/base.ts` and `packages/core/src/scoring/weights.ts`
both untouched, `WEIGHTS_VERSION` at 1.17 before and after, and no
`DataVersions` field moved. Same input, same pinned data versions, different
verdict. The cause is structural rather than careless: `DataVersions` stamps the
DATA (PSL, confusables, IP ranges, IDNA) and `WEIGHTS_VERSION` stamps the
WEIGHTS, so **neither stamps detector logic**, and a weight-0 informational
detector — `fqdn_root_label` is `scoring: false` — moves neither by design,
because there is no weight to bump.

**The antecedent is now the package version, because that is the stamp a caller
can actually pin.** `DataVersions` is emitted *on* the result; nobody installs
"linklint at data versions X". A caller installs a package version and is handed
whatever data that version ships. The old wording named something the reader
cannot control while omitting the one thing they can, so it was not merely false
— it was inactionable. This is also what §6.4's bump matrix had already decided:
its last row gives "package version + `CHANGELOG.md`" everything that is not the
result contract. A3's prose had not caught up with it.

**A detector-logic stamp was considered and declined.** A fourth stamp moving
whenever behavior could have changed is the most faithful reading of the
original intent, but the channel that actually failed here is already covered by
a stamp that exists. Under §6.4 a new reason code bumps `SCHEMA_VERSION`, and
A8's pin checks the `REASON_CODES` key set in beside the version it registered
under. Applied retroactively that rule catches `5813e01` exactly — it is the
pin's own worked example, and `fqdn_root_label` is in its key list today. What a
new stamp would add is only the residual: a detector that changes WHICH inputs
raise an EXISTING code, moving no registry key. That residual is what the
matrix's last row already assigns to the package version. Against it: a new
versioned artifact needs its own drift guard — realistically a behavioral digest
over the corpus, re-stamped on every intentional detector change — and a stale
one is worse than none, because it would assert "logic unchanged since X" while
being wrong. That is the `LINK-zsbeqtcr` shape this register exists to prevent,
so the stamp would import the very failure it was meant to close.

**A3's pin did not test A3.** It asserted `toContain("**Deterministic**")` — a
bare adjective that stays green under any antecedent, including the false one —
and referenced `dataVersions` nowhere, so the single clause that was wrong was
the single clause nothing tested. A guarantee whose pin does not bite is the same
defect class as an unpinned one. The test now matches the whole conditional in
both `README.md` and this file, required as the package version and refused as
the data versions, over whitespace-flattened and blockquote-stripped prose so a
hard wrap cannot make the match silently vacuous. The behavioral half gained a
cold re-import under a reset module registry: repeat-call and reversed-order
equality both observe one already-initialized module graph, so a lazily-built
table mutated on first use could survive both.

**A3 is also qualified, deliberately.** `pslSnapshot.stale` is the one time-relative
field on a result: it reflects wall-clock time at inspection, so two calls a
year apart can differ in that field alone. The qualification is already stated
on `PslSnapshot` in `packages/core/src/data/psl-provenance.ts` and is asserted
as an exclusion — not ignored — in the A3 test, with a verified negative
control that the flag really does flip under a moved clock.

**And it is one-directional (`LINK-elzuacby`).** The field is tri-state, and the
only positive claim it makes is staleness. The bundled snapshot date is a
`tldts` packaging-release date, which bounds the list's age from *below*: it can
show a snapshot is **at least** N days old, never that it is no older than N.
So `stale: true` is proven, `stale: null` is undetermined — the ordinary value
for the pinned bundle — and `stale: false` is emitted only from a `dateKind:
"exact"` provenance record, which no current dependency supplies. Consumers must
branch on `=== true`; treating `!== false` (or `!== true`) as a freshness signal
reads a claim linklint has never made. Pinned by
`packages/core/test/psl-provenance.test.ts` (both provenance kinds at the
window boundary, on an injected clock) and
`packages/cli/test/render.test.ts` (the CLI warns on `true` only).

**A8 is the mechanical half of the bump matrix (`LINK-zzydqrkd`).** The matrix
in `docs/architecture.md` §6.4 gives `SCHEMA_VERSION` the serialized result's
closed value domains, additive changes included, and `ReasonCode` — publicly
exported, `keyof typeof REASON_CODES` — is the central one. The weak guard for
it is a prose grep, which cannot separate a defect from the three correct
no-bump notes already in that document (§6.1.1, §6.1.2, §6.3). So the claim is
pinned instead of grepped: the registry key set is checked into
`docs-validation.test.ts` beside the version it registered under, and it
reddens both ways — a code added without a bump, and a bump that leaves the pin
stale. It would have caught `5813e01`, which added `fqdn_root_label` with
`schema/base.ts` untouched while every doc-sync assertion stayed green.
`CHANGELOG.md` names that miss and one other rather than baselining them.

## B. Package guarantees

Claims published in a package's own `## Guarantees` section — the ones a
consumer reads on npm.

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| B1 | `@linklint/cli`: no outbound network, no telemetry | `packages/cli/README.md` | `packages/cli/test/offline-guarantee.test.ts` |
| B2 | `@linklint/mcp`: no outbound network, no telemetry (stdio transport only) | `packages/mcp/README.md` | `packages/mcp/test/offline-guarantee.test.ts` |
| B3 | `@linklint/mcp`: every tool is annotated read-only and closed-world | `packages/mcp/README.md` | `packages/mcp/test/offline-guarantee.test.ts` |
| B4 | `@linklint/mcp` returns the exact core schema — the adapter never forks detector or scoring logic | `packages/mcp/README.md` | `packages/mcp/test/parity.test.ts` |
| B5 | `linklint check` never gains an implicit online mode; core never imports `@linklint/online`, and online never imports CLI or MCP | `docs/online-runtime-boundary.md` §3 | `packages/online/test/package-contract.test.ts` |

B1–B3 were **unpinned before `LINK-ltyjctpf`** — three published guarantees
with no test behind any of them, the exact `LINK-zsbeqtcr` shape. B3's
`readOnlyHint` was set in `tools/index.ts` and never asserted over the wire.

## C. Scoring invariants

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| C1 | Probabilistic-OR aggregation is order-independent and saturating — it approaches 1 but never passes it | `README.md`, `docs/scoring.md` | `packages/core/test/score.test.ts` |
| C2 | Weight-0 informational reasons never change the score | `README.md`, `docs/reason-codes.md` | `packages/core/test/score.test.ts` |
| C3 | Policy reasons carry `weight: 0` and never change `score` or `severity` | `README.md`, `docs/architecture.md` §5, `docs/reason-codes.md` | `packages/core/test/policy-channel-separation.test.ts` |
| C4 | Detectors never supply their own weight; core attaches it from the version-pinned table | `docs/architecture.md` §5, `docs/reason-codes.md`, `docs/layer3-reputation-model.md` | type-level — `CollectedFinding` has no `weight` field, so `tsc` rejects one |
| C5 | Suppression never hides itself: the `suppression` token appears in `checksRun` whenever the option is present, even as `[]` | `docs/architecture.md` §8, `docs/scoring.md` | `packages/core/test/suppress-reasons.test.ts` |
| C6 | With `suppressReasons` absent, output is byte-for-byte unchanged | `docs/scoring.md` | `packages/core/test/suppress-reasons.test.ts` |
| C7 | The count of codes that never move the score matches the registry — the prose states a number, not an adjective | `docs/scoring.md` | `packages/core/test/docs-validation.test.ts` (asserts the literal `The remaining **N** codes` against `REASON_CODES` weight-0 membership) |
| C8 | Two or more trailing dots never reach `fqdn_root_label` — they create an empty label and fail parsing first | `docs/reason-codes.md` (`fqdn_root_label`) | `packages/core/test/fqdn-root-label.test.ts` |

C4 follows the precedent already recorded in `docs-validation.test.ts`: a
property the type system makes unrepresentable needs no runtime test.

## D. Fail-closed and absence-is-not-safety

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| D1 | `status: "invalid"` carries `score: null` and `severity: null` — never a fallback to a second parser | `docs/architecture.md` §1.1, `docs/scoring.md` | `packages/core/test/invalid-gate-contract.test.ts` |
| D2 | A clean result is never rendered, described, or field-named as "safe" on any surface | `docs/architecture.md` §1.1, `README.md`, MCP tool descriptions | `packages/core/test/docs-validation.test.ts`, `packages/mcp/test/parity.test.ts` |
| D3 | An invalid URL is never assumed safe by the CLI exit policy | `packages/cli/README.md`, `docs/scoring.md` | `packages/cli/test/policy.test.ts` |
| D4 | Unconfigured L2/L3 layers stay skipped — a score never implies unfinished work was clean | `docs/architecture.md` §7, `docs/online-runtime-boundary.md` | `packages/core/test/inspect-async.test.ts` |
| D5 | A no-match is evidence about one source at one time, never a safety claim | `docs/layer3-reputation-model.md`, `docs/online-source-contract.md` | `packages/online/test/urlhaus-lookup.test.ts`, `packages/online/test/phishtank-lookup.test.ts` |
| D6 | Report what you can determine, never silently pass: a host that cannot resolve returns a weight-0 reason saying so, not an empty reason list | `docs/architecture.md` §1.1 | `packages/core/test/host-length-unresolvable.test.ts` |
| D9 | `status: "invalid"` never fixes the reason list or `checksRun`: findings that predate the parse failure are reported with `checksRun: ["lexical"]`, and the weight-0 `parse_error` with `checksRun: []` is only the fallback for when nothing else explains the failure | `docs/architecture.md` §6 | `packages/core/test/docs-validation.test.ts` |
| D10 | A weight on an invalid result is evidence, never arithmetic — `aggregate()` runs on the `ok` path only, so no `score` or `severity` may be re-derived from it | `docs/architecture.md` §6, `docs/scoring.md` | `packages/core/test/docs-validation.test.ts`, `packages/core/test/invalid-gate-contract.test.ts` |
| D8 | The parser's `stripInvisible` never strips U+2028/U+2029, so a line separator in the *host* stays fail-closed `invalid` rather than being stripped into a host that parses; the detector's set is wider than the parser's on purpose | `docs/reason-codes.md` (`invisible_char`) | `packages/core/test/line-separator.test.ts` |

| D7 | `checksRun` and `checksSkipped` never carry the same token — a failed policy axis is `policy:<axis id>` in the skip list while the `policy` channel token stays in the run list; a failed *dispatcher* is bare `policy` in the skip list and absent from the run list | `docs/architecture.md` §5 | `packages/core/test/policy-failure-injection.test.ts` |

**D9/D10 are the correction of a claim that had rotted (`LINK-qtenxsfi`).** §6's
Key-invariants block asserted `status: "invalid"` → "`parse_error` reason,
`checksRun: []`" — a pre-fourth-rule shape the serializer deliberately left
behind, unguarded and therefore false for months. D9 restates what
`buildInvalidResult` does; D10 settles the question the block had left open, on
which two readers had reached opposite conclusions: an invalid result carries
scoring weights at their registry values, and nothing aggregates them.

D6 is the fourth rule of §1.1, and `host_length_unresolvable` is its worked
case: a hostname over the 63-octet label or 253-octet name limit still scores
`0.00`/`benign` — the score is correct and does not move — but the result no
longer reads as "linklint had no opinion". The claim that such a host "will
never work" is a claim about DNS, and the test pins both halves that are ours:
that the reason fires at each limit and that the reason list is not empty.

## E. The name-never-create rule

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| E1 | The brand watchlist may only NAME a structural anomaly already found; it may never CREATE a finding | `README.md`, `docs/architecture.md` §1.1 | `packages/core/test/brand-fold-surface.test.ts` |
| E2 | A stale bundled PSL can never silently reintroduce the IMC '23 tenant-collapse harm | `docs/architecture.md` §7 | `packages/core/test/freshness-corpus.test.ts` |

## F. Enrichment and online boundary

| # | Guarantee | Stated in | Pinned by |
| --- | --- | --- | --- |
| F1 | Skipped, failed, and partial reports are never cached | `README.md`, `docs/architecture.md` §7, `docs/enrichment-outcomes.md` | `packages/core/test/enrichment-cache.test.ts` |
| F2 | The framework never derives cache key material from the full URL, and rejects a key that discloses it | `docs/architecture.md` §7, `docs/enrichment-outcomes.md` | `packages/core/test/enrichment-cache.test.ts` |
| F3 | Every pluggable call is a total boundary — an exception becomes an attributed failure outcome and never rejects `inspectAsync()` | `docs/enrichment-outcomes.md` | `packages/core/test/enrichment-resilience.test.ts` |
| F4 | Online evidence is additive and never replaces the lexical verdict | `docs/layer3-reputation-model.md`, `docs/online-source-contract.md`, `docs/reason-codes.md` | `packages/online/test/reputation-composition.test.ts` |
| F5 | Evidence-only sources (TLS, DNS) never score a finding and are byte-neutral on the verdict | `docs/layer3-reputation-model.md`, `docs/online-source-contract.md` | `packages/online/test/tls-certificate-enricher.test.ts`, `packages/online/test/dns-enricher.test.ts` |
| F6 | Redirects are returned to the caller and never followed implicitly; construction is never consent to connect | `packages/online/README.md`, `docs/safe-transport.md`, `docs/online-runtime-boundary.md` | `packages/online/test/safe-transport.test.ts` |
| F7 | Ambient credential headers are never copied to a destination; `Referer` is never forwarded from caller headers | `docs/safe-transport.md` | `packages/online/test/safe-transport.test.ts` |
| F8 | Local wrapper decoding never calls a vendor decoder service and performs no I/O at all | `packages/online/README.md`, `docs/wrapper-decoding.md`, `docs/redirect-chain-resolution.md` | `packages/online/test/embedded-wrapper.test.ts`, `packages/online/test/package-contract.test.ts` |
| F9 | A reputation match is never broadened to the host — a different path, query, subdomain, or parent is a `no-hit` | `docs/layer3-reputation-model.md`, `docs/reason-codes.md`, `docs/online-roadmap.md` | `packages/online/test/urlhaus-lookup.test.ts`, `packages/online/test/phishtank-lookup.test.ts` |
| F10 | The built-in Node transport never routes through Node's ambient proxy configuration — `HTTP_PROXY`/`HTTPS_PROXY`, `NODE_USE_ENV_PROXY`, or a runtime `http.setGlobalProxyFromEnv()` | `docs/safe-transport.md` | `packages/online/test/node-transport-live.test.ts`, `packages/online/test/node-transport-tls-live.test.ts` |
| F11 | The connector is never handed an address outside the set the hop's own resolution returned, and every member of that set is classified before one is selected | `docs/safe-transport.md` | `packages/online/test/safe-transport.test.ts` |
| F12 | A caller header value carrying CR, LF, or NUL is never forwarded to any HTTP port, caller-supplied ports included | `docs/safe-transport.md` | `packages/online/test/node-transport-headers.test.ts` |
| F13 | A caller header value the built-in HTTP/1.1 adapter cannot put on the wire ends the attempt as `incomplete` / `http-malformed` before the request is sent, and the cause never quotes the refused value; the sendable set is Latin-1, so `Accept-Language: de-DE, fr;q=0.9` and any value containing `ü` still reach the destination byte for byte | `docs/safe-transport.md` | `packages/online/test/node-transport-headers.test.ts` |
| F14 | A source is never constructed under terms it cannot honor and never silently downgraded to a weaker default — every reputation factory takes a required `terms` argument and runs `assertSourceTermsAccepted` before the enricher exists; the gate is terms-only and never demands a feed credential to construct a query-side enricher | `docs/online-source-contract.md`, `docs/online-runtime-boundary.md`, `docs/online-composition-root.md`, `packages/online/README.md` | `packages/online/test/contract/terms-gate-wiring.test.ts` |

**F10 is scoped to the built-ins, deliberately.** It is a claim about
`createNodeSafeTransport()`'s own connector and HTTP port, not about a
caller-supplied adapter — a custom port owns its own proxy behavior, and the
prose in `docs/safe-transport.md` states that limit rather than leaving a reader
to infer a wider promise. `LINK-xscdzrji` added the pin: the claim had been
published since the boundary shipped with nothing behind it, the same shape as
`LINK-zsbeqtcr`. Both regressions aim Node at a **dead loopback proxy
sentinel** and require the production `NodeConnectionPorts` path to reach a real
loopback destination anyway, so switching the built-in path to an ambient proxy
fails as a deterministic `ECONNREFUSED` with no external network. Each case
carries a live control — a default-global-agent request that must die on the
sentinel — because an isolation test whose proxy was never installed passes
vacuously.

**F11 is a closure claim, not a completeness one.** It says the pinned address
came from the returned set; it does *not* say the returned set is the
authoritative A/AAAA RRset. The built-in resolver is one
`dns.lookup(hostname, { all: true, verbatim: true })` — `getaddrinfo`, subject
to hosts-file/`nsswitch` sources, the stub-resolver cache, RFC 6724 filtering
and `AI_ADDRCONFIG`, and returning no TTL. `docs/safe-transport.md` states that
limit rather than leaving a reader to infer the wider promise. `LINK-rbghrpru`
added the pin: the prose across five documents and the published
`packages/online/README.md` read as the wider claim, and the suite had no case
with **two allowed answers at once**, so first-allowed selection and
set-membership were both unexercised — the same shape as `LINK-zsbeqtcr`. The
regression drives `pinDestination` directly, because it is the seam both
`safeFetch` and the TLS-observe path share, and re-checks the property through
a full session so the address the connector actually receives is compared
against the recorded set.

## G. Detector precision claims

The largest group — 81 claim lines in `docs/reason-codes.md` alone, nearly all
of the form *"`X` never fires for `Y`"*. These are **precision** claims (SC-2):
each names the false positive its detector deliberately declines to raise.

They are handled as a class rather than one register row each, because the
class has a structural pin: every detector owns a test file, and a precision
claim is only worth writing when the exemplar that motivated it is in that
file. The audit below verifies that link on a curated sample — each exemplar is
quoted from a `never` sentence in `docs/reason-codes.md`, and the ratchet test
asserts each appears in the test suite.

| Exemplar | Claim it pins |
| --- | --- |
| `1password` | `ascii_homoglyph` skips a leading-digit label |
| `blink182` | a disqualifying digit blocks the whole label |
| `bet365` | same, via a non-folding digit |
| `route53` | same, and it cannot reach a brand |
| `s3` | below the length floor |
| `web3` | non-folding digit |
| `i18n` | digits outnumber letters |
| `XN--CAF-DMA` | uppercase ACE round-trips, so `punycode_malformed` stays quiet |
| `cdn.assets` | a legitimate 3-label deep subdomain stays under the depth threshold |
| `myproject.github.io` | a brand-owned platform host on a sibling eTLD+1 does not trip API impersonation |
| `openai.example.com` | a brand word in an unrelated subdomain does not trip it either |
| `myoauth` | OAuth path matching is segment-anchored |
| `userrole` | prompt-injection parameter matching is set membership, not substring |
| `payroll` | same |
| `2001:DB8::1` | pure case differences are not an IPv6 canonicalization anomaly |
| `64:ff9b::808:808` | a NAT64 wrapper never manufactures a verdict for a public address |
| `0::1` | …while an uncompressed zero run is one |
| `пример` | a genuine non-Latin word never folds to pure ASCII |
| `россия` | same |
| `下載` | a pure non-ASCII run never fires `low_byte_truncation` — the code needs ASCII on both sides of the truncating code point |
| `한국어` | same, in Hangul |
| `İstanbul` | ordinary Turkish orthography never raises severity on its own |

One claim in this class was **not** covered by an exemplar and is now pinned
directly: *"a hostname is deliberately never a row"* in the cloud-metadata
table. Nothing asserted it, and a hostname row would match nothing while
inviting a resolver call that contradicts the zero-network contract. Pinned in
`packages/core/test/docs-validation.test.ts`.

**Residual, stated honestly.** This is a sampled audit, not an exhaustive
per-claim proof for all 81 lines. The judgment behind stopping there: a class-G
failure is a false positive on a named benign input, which the corpus and
boundary-baseline suites already sweep broadly, whereas a class-A or class-B
failure is a false *safety* claim reaching a caller — the asymmetry that
`LINK-zsbeqtcr` demonstrated. The budget ratchet means any *new* claim in this
class still has to be triaged when it is written.

## H. Not guarantees

Listed so that absence from the register above reads as a decision rather than
an oversight. These lines match the pattern and are deliberately unpinned:

- **Hedged frequency claims** — "almost never legitimate" (`dangerous_scheme`),
  "almost always accidental" (`idn_host`), "legitimate sites rarely stack bait
  words in the host". These are stated *as* probabilistic rationale for a
  weight; pinning them would be pinning the rationale, not the behavior. The
  behavior they justify is pinned by the detector's own tests.
- **Historical narration** — "Former Epic O was never part of this
  implementation roadmap", "one real locale-dependence defect existed and is
  fixed", "branch protection, which this project has never had on either host"
  and the `[SCRATCHED]` row's "the code never merged"
  (`docs/local-workflow.md`, `docs/tracker-hygiene.md`). Statements about the
  past, not about current behavior. The pair
  "failing to score it was always correct; failing to *mention* it was not"
  (`docs/architecture.md` §1.1 and `docs/reason-codes.md`) belongs here too: it
  narrates why the fourth rule was added, and the behavior it argues for is
  D6 above.
- **Process rules** — "reopen only against a concrete named gap — never by
  importing a list wholesale" (§6.1.3, binding the next proposer rather than the
  code), "parked work is never selected by an agent choosing what
  is next", "caller-owned mirrors are never silently redistributed". These bind
  contributors, not code; the tracker and review enforce them.
- **`always` as a discourse marker** — "the match is always recorded as
  evidence" restates a mechanism described in the same paragraph rather than
  adding a separate promise.
- **Literal configuration values** — `gc.reflogExpire=never` and
  `gc.reflogExpireUnreachable=never` (`docs/local-workflow.md`) are git config
  tokens quoted verbatim. The word is the value being set, not a promise about
  linklint.
- **References to this register** — the `README.md` repository-layout row that
  points here matches the pattern by naming it, and
  `docs/tracker-hygiene.md`'s "the same doctrine governs unconditional prose
  claims" points here from the decision-record rule. A label is not a claim.
- **Descriptions of a *declined* design** — §6.1.3's "a skeleton table decoupled
  from `BRAND_DOMAINS` so `brand_homoglyph` never sees it" describes the narrow
  widening the section goes on to decline. It states what the rejected design
  would have done, so there is no behavior to pin; the section's actual
  disposition is the decline.
- **Cross-references to a rule stated elsewhere** — "§5's result-invariant list",
  "satisfies §1.1's name-never-create rule" (also in `docs/reason-codes.md`, where `open_redirect_param`'s rejected-alternatives bullet names the rule that forbids an IdP allowlist), and §6.4's "§6's invariant list"
  naming the block whose `Reason.suppressed` bullet it corrects. These point at
  a claim rather than making one; the claim is pinned where it is stated — D7,
  E1, and, for §6's block, D9/D10 plus the §6 assertions in
  `packages/core/test/docs-validation.test.ts`.
- **Requirements imposed on a caller's implementation** — "a reader must never
  observe a partial dataset" (`packages/online/README.md`) states the atomicity
  the snapshot updaters *rely on* from a `replace` the caller supplies. It binds
  the caller's store, not linklint's code, so there is nothing here for our
  suite to pin: the store is an interface (`docs/online-runtime-boundary.md`
  gives the directory and the durability policy to the deployment), and the
  README's write-then-rename sketch is one way to satisfy it, not a promise that
  it holds. Same category as the process rules above — it binds an implementor.
  Whether `@linklint/online` should ship its own fs-backed store, and so make
  this a claim we could pin, is `LINK-tkafhtrf`.

## Adding a claim

If `pnpm check` fails on the claim budget, you added or removed an
unconditional word. Do one of:

1. **Pin it** — add the test, add the register row, bump the budget.
2. **Qualify it** — rewrite the sentence so it stops promising more than the
   code delivers, then bump the budget.
3. **Classify it as §H** — if it is genuinely rhetorical, note it there and
   bump the budget.

Bumping the budget without doing one of the three is how `LINK-zsbeqtcr`
happened.
